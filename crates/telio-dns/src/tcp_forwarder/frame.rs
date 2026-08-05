use crate::packet_decoder::{find_nord_query, parse_dns_query_packet};

pub(crate) const DNS_TCP_LEN_PREFIX: usize = 2;

/// Incremental frame reassembler.
#[derive(Default)]
pub(crate) struct MessageReader {
    buf: Vec<u8>,
}

impl MessageReader {
    /// Push bytes into the buffer
    pub(crate) fn push(&mut self, bytes: &[u8]) {
        self.buf.extend_from_slice(bytes);
    }

    /// Take the next complete frame, prefix included, if one has arrived.
    pub(crate) fn next_frame(&mut self) -> Option<Vec<u8>> {
        let &[hi, lo] = self.buf.get(..DNS_TCP_LEN_PREFIX)? else {
            return None;
        };
        let frame_len = DNS_TCP_LEN_PREFIX + usize::from(u16::from_be_bytes([hi, lo]));
        if self.buf.len() < frame_len {
            return None;
        }
        Some(self.buf.drain(..frame_len).collect())
    }

    /// Len of bytes currently buffered.
    pub(crate) fn partial_len(&self) -> usize {
        self.buf.len()
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
        assert_eq!(reader.next_frame(), Some(complete));
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
        assert_eq!(reader.next_frame(), Some(complete));
    }

    #[test]
    fn reader_yields_two_frames_from_one_push() {
        let mut reader = MessageReader::default();
        let first = frame(b"one");
        let second = frame(b"two");
        let mut both = first.clone();
        both.extend_from_slice(&second);

        reader.push(&both);
        assert_eq!(reader.next_frame(), Some(first));
        assert_eq!(reader.next_frame(), Some(second));
        assert_eq!(reader.next_frame(), None);
    }

    #[test]
    fn reader_yields_frames_of_boundary_sizes() {
        let mut reader = MessageReader::default();
        reader.push(&[0x00, 0x00]);
        assert_eq!(reader.next_frame(), Some(vec![0x00, 0x00]));

        let maximal = frame(&vec![0xAA; u16::MAX as usize]);
        assert_eq!(maximal.len(), DNS_TCP_MAX_FRAME);
        reader.push(&maximal);
        assert_eq!(reader.next_frame(), Some(maximal));
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
