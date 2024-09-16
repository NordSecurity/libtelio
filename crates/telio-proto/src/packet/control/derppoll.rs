use crate::messages::derppoll::{DerpPollRequest, DerpPollResponse};
use crate::{
    Codec, CodecError, CodecResult, DowncastPacket, PacketControl, PacketTypeControl, Session,
    MAX_PACKET_SIZE,
};
use bytes::BufMut;
use protobuf::{Message, RepeatedField};
use std::collections::{HashMap, HashSet};
use std::convert::TryInto;
use telio_crypto::PublicKey;

/// peer -> is_online
pub type PeersStatesMap = HashMap<PublicKey, bool>;

/// # Examples
/// Encoding and decoding poll request message:
/// ```rust
/// use telio_crypto::PublicKey;
/// use telio_proto::{Codec, DerpPollRequestMsg, PacketTypeControl};
/// use std::collections::HashSet;
/// const PEER1: [u8; 32] = [3u8; 32];
/// const PEER2: [u8; 32] = [5u8; 32];
///
/// let mut peers = HashSet::new();
/// peers.insert(PublicKey::from(&PEER1));
/// peers.insert(PublicKey::from(&PEER2));
///
/// let req = DerpPollRequestMsg::new(
/// 19_u64,
/// &peers,
/// );
///
/// let encoded = req.encode().unwrap();
/// let decoded =
///     DerpPollRequestMsg::decode(encoded.as_slice()).expect("Failed to parse packet");
///
/// let peers = decoded.get_peers();
/// assert_eq!(peers.len(), 2);
/// ```
#[derive(Debug, PartialEq, Clone)]
pub struct DerpPollRequestMsg {
    session: Session,
    msg: DerpPollRequest,
}

impl DerpPollRequestMsg {
    /// Creates new request message from `peers`.
    pub fn new(session: Session, peers: &HashSet<PublicKey>) -> Self {
        Self {
            session,
            msg: DerpPollRequest {
                peers: RepeatedField::from_vec(peers.iter().map(|peer| peer.to_string()).collect()),
                ..Default::default()
            },
        }
    }

    /// Get unique session number
    pub fn get_session(&self) -> Session {
        self.session
    }

    /// Get requested peers
    pub fn get_peers(&self) -> Vec<PublicKey> {
        self.msg
            .peers
            .iter()
            .filter_map(|peer| peer.parse().ok())
            .collect()
    }
}

impl Codec<PacketTypeControl> for DerpPollRequestMsg {
    const TYPES: &'static [PacketTypeControl] = &[PacketTypeControl::DerpPollRequest];

    fn decode(bytes: &[u8]) -> CodecResult<Self>
    where
        Self: Sized,
    {
        if bytes.is_empty() {
            return Err(CodecError::InvalidLength);
        }
        let packet_type =
            PacketTypeControl::from(*bytes.first().unwrap_or(&(PacketTypeControl::Invalid as u8)));
        match packet_type {
            PacketTypeControl::DerpPollRequest => {
                let bytes = bytes.get(1..).ok_or(CodecError::InvalidLength)?;
                let session = bytes
                    .get(0..8)
                    .ok_or(CodecError::InvalidLength)?
                    .try_into()
                    .map_err(|_| CodecError::InvalidLength)
                    .map(Session::from_be_bytes)?;
                let poll_request = DerpPollRequest::parse_from_bytes(
                    bytes.get(8..).ok_or(CodecError::InvalidLength)?,
                );
                Ok(Self {
                    session,
                    msg: poll_request.map_err(|_| CodecError::DecodeFailed)?,
                })
            }
            _ => Err(CodecError::DecodeFailed),
        }
    }

    fn encode(self) -> CodecResult<Vec<u8>> {
        let mut bytes = Vec::with_capacity(MAX_PACKET_SIZE);
        bytes.put_u8(PacketTypeControl::DerpPollRequest as u8);
        bytes.put_u64(self.session);
        self.msg
            .write_to_vec(&mut bytes)
            .map_err(|_| CodecError::Encode)?;

        Ok(bytes)
    }

    fn packet_type(&self) -> PacketTypeControl {
        PacketTypeControl::DerpPollRequest
    }
}

impl DowncastPacket<PacketControl> for DerpPollRequestMsg {
    fn downcast(packet: PacketControl) -> Result<Self, PacketControl>
    where
        Self: Sized,
    {
        match packet {
            PacketControl::DerpPollRequest(data) => Ok(data),
            packet => Err(packet),
        }
    }
}

impl std::fmt::Display for DerpPollRequestMsg {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Derp poll request {}, peers requested: {:?}",
            self.session, self.msg.peers
        )
    }
}

/// Reply to `DerpPollResponseMsg`
/// # Examples
/// Decoding poll response message:
/// ```rust
/// use telio_crypto::PublicKey;
/// use telio_proto::{Codec, DerpPollResponseMsg, PacketTypeControl};
/// const PEER1: [u8; 32] = [3u8; 32];
/// const PEER2: [u8; 32] = [5u8; 32];
/// const RESPONSE_BYTES_TWO_PEERS: [u8; 109] = [
///     1, 0, 0, 0, 0, 0, 0, 0, 101, 10, 48, 10, 44, 66, 81, 85, 70, 66, 81, 85, 70, 66, 81, 85,
///     70, 66, 81, 85, 70, 66, 81, 85, 70, 66, 81, 85, 70, 66, 81, 85, 70, 66, 81, 85, 70, 66, 81,
///     85, 70, 66, 81, 85, 70, 66, 81, 85, 61, 16, 0, 10, 48, 10, 44, 65, 119, 77, 68, 65, 119,
///     77, 68, 65, 119, 77, 68, 65, 119, 77, 68, 65, 119, 77, 68, 65, 119, 77, 68, 65, 119, 77,
///     68, 65, 119, 77, 68, 65, 119, 77, 68, 65, 119, 77, 68, 65, 119, 77, 61, 16, 1,
/// ];
/// let data = DerpPollResponseMsg::decode(RESPONSE_BYTES_TWO_PEERS.as_slice())
///     .expect("Failed to parse packet");
/// assert_eq!(data.packet_type(), PacketTypeControl::DerpPollResponse);
/// assert_eq!(data.get_session(), 101_u64);
/// let peers = data.get_peers_statuses();
/// assert_eq!(peers.len(), 2);
/// assert_eq!(peers.get(&PublicKey::from(&PEER1)), Some(&true));
/// assert_eq!(peers.get(&PublicKey::from(&PEER2)), Some(&false));
/// ```
#[derive(Debug, PartialEq, Clone)]
pub struct DerpPollResponseMsg {
    session: Session,
    msg: DerpPollResponse,
}

impl DerpPollResponseMsg {
    /// Creates new request message from `peers`.
    pub fn new(session: Session, peer_states: HashMap<PublicKey, bool>) -> Self {
        Self {
            session,
            msg: DerpPollResponse {
                peer_states: peer_states
                    .iter()
                    .map(|(pk, state)| (pk.to_string(), *state))
                    .collect(),
                ..Default::default()
            },
        }
    }

    /// Get unique session number
    pub fn get_session(&self) -> Session {
        self.session
    }

    /// Get requested peer statuses
    pub fn get_peers_statuses(&self) -> HashMap<PublicKey, bool> {
        self.msg
            .peer_states
            .iter()
            .filter_map(|(peer, state)| peer.parse().ok().map(|pk| (pk, *state)))
            .collect()
    }
}

impl Codec<PacketTypeControl> for DerpPollResponseMsg {
    const TYPES: &'static [PacketTypeControl] = &[PacketTypeControl::DerpPollResponse];

    fn decode(bytes: &[u8]) -> CodecResult<Self>
    where
        Self: Sized,
    {
        if bytes.is_empty() {
            return Err(CodecError::InvalidLength);
        }
        let packet_type =
            PacketTypeControl::from(*bytes.first().unwrap_or(&(PacketTypeControl::Invalid as u8)));
        match packet_type {
            PacketTypeControl::DerpPollResponse => {
                let bytes = bytes.get(1..).ok_or(CodecError::InvalidLength)?;
                let session = bytes
                    .get(0..8)
                    .ok_or(CodecError::InvalidLength)?
                    .try_into()
                    .map_err(|_| CodecError::InvalidLength)
                    .map(Session::from_be_bytes)?;
                let poll_request = DerpPollResponse::parse_from_bytes(
                    bytes.get(8..).ok_or(CodecError::InvalidLength)?,
                );
                Ok(Self {
                    session,
                    msg: poll_request.map_err(|_| CodecError::DecodeFailed)?,
                })
            }
            _ => Err(CodecError::DecodeFailed),
        }
    }

    fn encode(self) -> CodecResult<Vec<u8>> {
        let mut bytes = Vec::with_capacity(MAX_PACKET_SIZE);
        bytes.put_u8(PacketTypeControl::DerpPollResponse as u8);
        bytes.put_u64(self.session);
        self.msg
            .write_to_vec(&mut bytes)
            .map_err(|_| CodecError::Encode)?;

        Ok(bytes)
    }

    fn packet_type(&self) -> PacketTypeControl {
        PacketTypeControl::DerpPollResponse
    }
}

impl DowncastPacket<PacketControl> for DerpPollResponseMsg {
    fn downcast(packet: PacketControl) -> Result<Self, PacketControl>
    where
        Self: Sized,
    {
        match packet {
            PacketControl::DerpPollResponse(data) => Ok(data),
            packet => Err(packet),
        }
    }
}

impl std::fmt::Display for DerpPollResponseMsg {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Derp poll response {}, peer statuses: {:?}",
            self.session, self.msg.peer_states
        )
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::*;

    const PEER1: [u8; 32] = [3u8; 32];
    const PEER2: [u8; 32] = [5u8; 32];
    const REQUEST_BYTES_EMPTY: [u8; 9] = [0, 0, 0, 0, 0, 0, 0, 0, 100];
    const REQUEST_BYTES_TWO_PEERS: [u8; 101] = [
        0, 0, 0, 0, 0, 0, 0, 0, 19, 10, 44, 65, 119, 77, 68, 65, 119, 77, 68, 65, 119, 77, 68, 65,
        119, 77, 68, 65, 119, 77, 68, 65, 119, 77, 68, 65, 119, 77, 68, 65, 119, 77, 68, 65, 119,
        77, 68, 65, 119, 77, 68, 65, 119, 77, 61, 10, 44, 66, 81, 85, 70, 66, 81, 85, 70, 66, 81,
        85, 70, 66, 81, 85, 70, 66, 81, 85, 70, 66, 81, 85, 70, 66, 81, 85, 70, 66, 81, 85, 70, 66,
        81, 85, 70, 66, 81, 85, 70, 66, 81, 85, 61,
    ];

    const RESPONSE_BYTES_EMPTY: [u8; 9] = [1, 0, 0, 0, 0, 0, 0, 0, 101];
    const RESPONSE_BYTES_TWO_PEERS: [u8; 109] = [
        1, 0, 0, 0, 0, 0, 0, 0, 101, 10, 48, 10, 44, 66, 81, 85, 70, 66, 81, 85, 70, 66, 81, 85,
        70, 66, 81, 85, 70, 66, 81, 85, 70, 66, 81, 85, 70, 66, 81, 85, 70, 66, 81, 85, 70, 66, 81,
        85, 70, 66, 81, 85, 70, 66, 81, 85, 61, 16, 0, 10, 48, 10, 44, 65, 119, 77, 68, 65, 119,
        77, 68, 65, 119, 77, 68, 65, 119, 77, 68, 65, 119, 77, 68, 65, 119, 77, 68, 65, 119, 77,
        68, 65, 119, 77, 68, 65, 119, 77, 68, 65, 119, 77, 68, 65, 119, 77, 61, 16, 1,
    ];

    #[test]
    fn encode_request() {
        // test empty message
        let req = DerpPollRequestMsg::new(100_u64, &HashSet::new());

        let encoded = req.encode().unwrap();
        assert_eq!(encoded, REQUEST_BYTES_EMPTY.as_slice());

        let mut peers = HashSet::new();
        peers.insert(PublicKey::from(&PEER1));
        peers.insert(PublicKey::from(&PEER2));
        // test message with two peers
        let mut req = DerpPollRequestMsg::new(19_u64, &peers);
        req.msg.peers.sort();
        let encoded = req.encode().unwrap();
        assert_eq!(encoded, REQUEST_BYTES_TWO_PEERS);
    }

    #[test]
    fn decode_request() {
        // test empty message
        let data = DerpPollRequestMsg::decode(REQUEST_BYTES_EMPTY.as_slice())
            .expect("Failed to parse packet");
        assert_eq!(data.packet_type(), PacketTypeControl::DerpPollRequest);
        assert_eq!(data.get_session(), 100_u64);
        let peers = data.get_peers();
        assert_eq!(peers.len(), 0);

        // test message with two peers
        let data = DerpPollRequestMsg::decode(REQUEST_BYTES_TWO_PEERS.as_slice())
            .expect("Failed to parse packet");
        assert_eq!(data.packet_type(), PacketTypeControl::DerpPollRequest);
        assert_eq!(data.get_session(), 19_u64);
        let peers = data.get_peers();
        assert_eq!(peers.len(), 2);
        assert_eq!(peers[0].0, PEER1);
        assert_eq!(peers[1].0, PEER2);
    }

    #[test]
    fn encode_response() {
        // test empty message
        let req = DerpPollResponseMsg::new(101_u64, HashMap::from([]));

        let encoded = req.encode().unwrap();
        assert_eq!(encoded, RESPONSE_BYTES_EMPTY.as_slice());

        // test message with two peers
        let req = DerpPollResponseMsg::new(
            101_u64,
            HashMap::from([
                (PublicKey::from(&PEER1), true),
                (PublicKey::from(&PEER2), false),
            ]),
        );

        let encoded = req.encode().unwrap();
        let decoded =
            DerpPollResponseMsg::decode(encoded.as_slice()).expect("Failed to parse packet");
        assert_eq!(decoded.get_session(), 101_u64);
        assert_eq!(
            decoded.get_peers_statuses().get(&PublicKey::from(&PEER1)),
            Some(&true)
        );
        assert_eq!(
            decoded.get_peers_statuses().get(&PublicKey::from(&PEER2)),
            Some(&false)
        );
    }

    #[test]
    fn decode_response() {
        // test empty message
        let data = DerpPollResponseMsg::decode(RESPONSE_BYTES_EMPTY.as_slice())
            .expect("Failed to parse packet");
        assert_eq!(data.packet_type(), PacketTypeControl::DerpPollResponse);
        assert_eq!(data.get_session(), 101_u64);
        let peers = data.get_peers_statuses();
        assert_eq!(peers.len(), 0);

        // test message with two peers
        let data = DerpPollResponseMsg::decode(RESPONSE_BYTES_TWO_PEERS.as_slice())
            .expect("Failed to parse packet");
        assert_eq!(data.packet_type(), PacketTypeControl::DerpPollResponse);
        assert_eq!(data.get_session(), 101_u64);
        let peers = data.get_peers_statuses();
        assert_eq!(peers.len(), 2);
        assert_eq!(peers.get(&PublicKey::from(&PEER1)), Some(&true));
        assert_eq!(peers.get(&PublicKey::from(&PEER2)), Some(&false));
    }

    #[test]
    fn fail_to_decode_small_packet() {
        let bytes = &[];
        let data = DerpPollRequestMsg::decode(bytes);
        assert_eq!(data, Err(CodecError::InvalidLength));
    }

    #[test]
    fn fail_to_decode_packet_of_wrong_type() {
        let bytes = &[PacketTypeControl::Invalid as u8, 3, 1, 7, 6];
        let data = DerpPollRequestMsg::decode(bytes);
        assert_eq!(data, Err(CodecError::DecodeFailed));
    }
}
