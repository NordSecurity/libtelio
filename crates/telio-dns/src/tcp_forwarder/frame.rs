use crate::packet_decoder::{find_nord_query, parse_dns_query_packet};
use bytes::{Bytes, BytesMut};

pub(crate) const DNS_TCP_LEN_PREFIX: usize = 2;

/// Incremental frame reassembler.
#[derive(Default)]
pub(crate) struct MessageReader {
    buf: BytesMut,
}

impl MessageReader {
    /// Push bytes up to the end of the current frame, returns how many were taken.
    pub(crate) fn push(&mut self, bytes: &[u8]) -> usize {
        let prefix_missing = DNS_TCP_LEN_PREFIX.saturating_sub(self.buf.len());
        let (prefix, rest) = bytes.split_at(prefix_missing.min(bytes.len()));
        self.buf.extend_from_slice(prefix);
        let Some(frame_len) = self.frame_len() else {
            return prefix.len();
        };
        let body = rest
            .get(..frame_len.saturating_sub(self.buf.len()))
            .unwrap_or(rest);
        // Reserve the whole frame once its length is known.
        self.buf.reserve(frame_len.saturating_sub(self.buf.len()));
        self.buf.extend_from_slice(body);
        prefix.len() + body.len()
    }

    /// Take the frame once it is complete.
    pub(crate) fn next_frame(&mut self) -> Option<Bytes> {
        if self.buf.len() < self.frame_len()? {
            return None;
        }
        Some(std::mem::take(&mut self.buf).freeze())
    }

    /// Length of the frame at the head of the buffer.
    fn frame_len(&self) -> Option<usize> {
        let &[hi, lo] = self.buf.get(..DNS_TCP_LEN_PREFIX)? else {
            return None;
        };
        Some(DNS_TCP_LEN_PREFIX + usize::from(u16::from_be_bytes([hi, lo])))
    }

    /// Len of bytes currently buffered.
    pub(crate) fn partial_len(&self) -> usize {
        self.buf.len()
    }

    /// Clear the buffered bytes.
    pub(crate) fn clear(&mut self) {
        self.buf.clear();
    }
}

/// Check if request frame contains a `.nord` name.
pub(crate) fn is_nord_frame(frame: &[u8]) -> bool {
    let Some(message) = frame.get(DNS_TCP_LEN_PREFIX..) else {
        return false;
    };
    let Ok(packet) = parse_dns_query_packet(message) else {
        return false;
    };
    find_nord_query(&packet).is_some()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tcp_forwarder::test_utils::{frame, framed_query};

    pub(crate) const DNS_TCP_MAX_FRAME: usize = DNS_TCP_LEN_PREFIX + u16::MAX as usize;

    #[test]
    fn reader_withholds_a_frame_until_complete_and_tracks_its_length() {
        let mut reader = MessageReader::default();
        let complete = frame(b"query");

        assert_eq!(reader.partial_len(), 0, "nothing buffered at a boundary");
        reader.push(&complete[..3]);
        assert_eq!(reader.partial_len(), 3);
        assert!(reader.next_frame().is_none());

        reader.push(&complete[3..]);
        assert_eq!(reader.next_frame(), Some(complete.into()));
        assert_eq!(reader.partial_len(), 0, "back to a boundary once drained");
    }

    #[test]
    fn reader_reassembles_a_prefix_split_across_pushes() {
        let mut reader = MessageReader::default();
        let complete = frame(b"ab");

        reader.push(&complete[..1]);
        assert!(
            reader.next_frame().is_none(),
            "half a length prefix is not a frame"
        );
        reader.push(&complete[1..]);
        assert_eq!(reader.next_frame(), Some(complete.into()));
    }

    #[test]
    fn reader_takes_bytes_only_up_to_the_frame_boundary() {
        let mut reader = MessageReader::default();
        let first = frame(b"one");
        let second = frame(b"two");
        let mut both = first.clone();
        both.extend_from_slice(&second);

        let taken = reader.push(&both);
        assert_eq!(taken, first.len(), "the second frame is left to the caller");
        assert_eq!(
            reader.push(&both[taken..]),
            0,
            "nothing more until the frame is taken"
        );
        assert_eq!(reader.next_frame(), Some(first.into()));

        assert_eq!(reader.push(&both[taken..]), second.len());
        assert_eq!(reader.next_frame(), Some(second.into()));
        assert_eq!(reader.next_frame(), None);
    }

    #[test]
    fn reader_yields_frames_of_boundary_sizes() {
        let mut reader = MessageReader::default();
        reader.push(&[0x00, 0x00]);
        assert_eq!(reader.next_frame(), Some(vec![0x00, 0x00].into()));

        let maximal = frame(&vec![0xAA; u16::MAX as usize]);
        assert_eq!(maximal.len(), DNS_TCP_MAX_FRAME);
        reader.push(&maximal);
        assert_eq!(reader.next_frame(), Some(maximal.into()));
        assert_eq!(reader.partial_len(), 0);
    }

    #[test]
    fn reader_ignores_an_empty_push() {
        let mut reader = MessageReader::default();

        reader.push(&[]);
        assert_eq!(reader.partial_len(), 0);
        assert!(reader.next_frame().is_none());

        let complete = frame(b"query");
        reader.push(&complete[..3]);
        reader.push(&[]);
        assert_eq!(
            reader.partial_len(),
            3,
            "an empty push must not change an in-progress frame"
        );
        assert!(reader.next_frame().is_none());
    }

    #[test]
    fn a_maximal_frame_arriving_in_chunks_is_buffered_without_doubling() {
        let mut reader = MessageReader::default();
        let maximal = frame(&vec![0xAA; u16::MAX as usize]);

        for chunk in maximal.chunks(4096) {
            reader.push(chunk);
            assert_eq!(
                reader.buf.capacity(),
                DNS_TCP_MAX_FRAME,
                "the frame is reserved once its length is known"
            );
        }
        assert_eq!(reader.next_frame(), Some(maximal.into()));
        assert_eq!(
            reader.buf.capacity(),
            0,
            "the taken frame owns the allocation"
        );
    }

    #[test]
    fn a_nord_frame_is_recognized_whatever_its_case() {
        assert!(is_nord_frame(&framed_query(&[b"test", b"nord"])));
        assert!(is_nord_frame(&framed_query(&[b"TeSt", b"NORD"])));
        assert!(is_nord_frame(&framed_query(&[b"nord"])), "the bare zone");
    }

    #[test]
    fn the_length_prefix_is_not_part_of_the_message() {
        let framed = framed_query(&[b"test", b"nord"]);

        assert!(is_nord_frame(&framed));
        assert!(
            !is_nord_frame(&framed[DNS_TCP_LEN_PREFIX..]),
            "the first two bytes are always consumed as the prefix"
        );
    }
}
