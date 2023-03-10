use bytes::BufMut;
use std::convert::TryFrom;

use super::{PeerId, WGPort};
use crate::{
    messages::pinger::*, Codec, CodecError, CodecResult, DowncastPacket, Packet, PacketType,
    Session, MAX_PACKET_SIZE,
};
use protobuf::Message;

/// Unix timestamp in milliseconds
pub type Timestamp = u64;

/// Packet encapsulating containing WG packets
/// # Examples
/// Decoding ping message:
/// ```rust
/// # use crate::telio_proto::{Codec, PingerMsg, PingType, PacketType};
/// let bytes = &[7, 0, 8, 16, 9, 24, 128, 2];
/// let data = PingerMsg::decode(bytes).expect("Failed to parse packet");
/// assert_eq!(data.packet_type(), PacketType::Pinger);
/// assert_eq!(data.get_wg_port().0, 8_u16);
/// assert_eq!(data.get_session(), 9_u64);
/// assert_eq!(data.get_message_type(), PingType::PING);
/// assert_eq!(data.get_start_timestamp(), 256_u64);
///
/// assert_eq!(bytes, data.encode().unwrap().as_slice());
/// ```
/// Decoding pong message:
/// ```rust
/// # use crate::telio_proto::{Codec, PingerMsg, PingType, PacketType};
/// let bytes = &[7, 0, 6, 8, 1, 16, 8, 24, 128, 4];
/// let data = PingerMsg::decode(bytes).expect("Failed to parse packet");
/// assert_eq!(data.packet_type(), PacketType::Pinger);
/// assert_eq!(data.get_wg_port().0, 6_u16);
/// assert_eq!(data.get_session(), 8_u64);
/// assert_eq!(data.get_start_timestamp(), 512_u64);
/// assert_eq!(data.get_message_type(), PingType::PONG);
///
/// assert_eq!(bytes, data.encode().unwrap().as_slice());
/// ```
#[derive(Debug, PartialEq, Clone)]
pub struct PingerMsg {
    wg_port: WGPort,
    msg: Pinger,
}

// TODO this should also be put in protobuf format
impl PingerMsg {
    /// Create new ping packet (request)
    pub fn ping(wg_port: WGPort, session: Session, ts: Timestamp) -> Self {
        Self {
            wg_port,
            msg: Pinger {
                message_type: Pinger_Type::PING,
                session,
                start_timestamp: ts,
                ..Default::default()
            },
        }
    }

    /// Create new pong packet (response)
    pub fn pong(&self, wg_port: WGPort) -> Option<Self> {
        if self.msg.get_message_type() == Pinger_Type::PING {
            return Some(Self {
                wg_port,
                msg: Pinger {
                    message_type: Pinger_Type::PONG,
                    session: self.msg.session,
                    start_timestamp: self.msg.get_start_timestamp(),
                    ..Default::default()
                },
            });
        }

        None
    }

    /// Get WG Port
    pub fn get_wg_port(&self) -> WGPort {
        WGPort(self.wg_port.0 as u16)
    }

    /// Returns [`Pinger_Type`] of the message
    pub fn get_message_type(&self) -> Pinger_Type {
        self.msg.get_message_type()
    }

    /// Get unique session number
    pub fn get_session(&self) -> Session {
        self.msg.get_session()
    }

    /// Get ping start ts
    pub fn get_start_timestamp(&self) -> Timestamp {
        self.msg.get_start_timestamp()
    }
}

impl Codec for PingerMsg {
    const TYPES: &'static [PacketType] = &[PacketType::Pinger];

    fn decode(bytes: &[u8]) -> CodecResult<Self>
    where
        Self: Sized,
    {
        if bytes.is_empty() {
            return Err(CodecError::InvalidLength);
        }
        match PacketType::from(bytes[0]) {
            PacketType::Pinger => {
                if let Ok(wg_port) =
                    WGPort::try_from(bytes.get(1..3).ok_or(CodecError::InvalidLength)?)
                {
                    let pinger = Pinger::parse_from_bytes(&bytes[3..]);
                    return Ok(Self {
                        wg_port,
                        msg: pinger.map_err(|_| CodecError::DecodeFailed)?,
                    });
                }

                Err(CodecError::DecodeFailed)
            }
            _ => Err(CodecError::DecodeFailed),
        }
    }

    fn encode(self) -> CodecResult<Vec<u8>> {
        let mut bytes = Vec::with_capacity(MAX_PACKET_SIZE);

        bytes.put_u8(PacketType::Pinger as u8);
        bytes.put_u16(self.wg_port.0);
        self.msg
            .write_to_vec(&mut bytes)
            .map_err(|_| CodecError::Encode)?;

        Ok(bytes)
    }

    fn packet_type(&self) -> PacketType {
        PacketType::Pinger
    }
}

impl DowncastPacket for PingerMsg {
    fn downcast(packet: Packet) -> Result<Self, Packet>
    where
        Self: Sized,
    {
        match packet {
            Packet::Pinger(data) => Ok(data),
            packet => Err(packet),
        }
    }
}

impl std::fmt::Display for PingerMsg {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} wg_port: {}, session: {}, start_ts: {}",
            match self.get_message_type() {
                Pinger_Type::PING => "Ping: ",
                Pinger_Type::PONG => "Pong: ",
            },
            self.get_wg_port().0,
            self.get_session(),
            self.get_start_timestamp()
        )
    }
}

/// Packet encapsulating containing WG packets
#[derive(Debug, PartialEq, Clone)]
pub struct PingerMsgDeprecated {
    peer_id: PeerId,
    msg: Pinger,
}

// TODO this should also be put in protobuf format
impl PingerMsgDeprecated {
    /// Create new ping packet (request)
    pub fn ping(peer_id: PeerId, session: Session, ts: Timestamp) -> Self {
        Self {
            peer_id,
            msg: Pinger {
                message_type: Pinger_Type::PING,
                session,
                start_timestamp: ts,
                ..Default::default()
            },
        }
    }

    /// Create new pong packet (response)
    pub fn pong(&self, peer_id: PeerId) -> Option<Self> {
        if self.msg.get_message_type() == Pinger_Type::PING {
            return Some(Self {
                peer_id,
                msg: Pinger {
                    message_type: Pinger_Type::PONG,
                    session: self.msg.session,
                    start_timestamp: self.msg.get_start_timestamp(),
                    ..Default::default()
                },
            });
        }

        None
    }

    /// Get peer id
    pub fn get_peer_id(&self) -> PeerId {
        PeerId(self.peer_id.0 as u16)
    }

    /// Returns [`Pinger_Type`] of the message
    pub fn get_message_type(&self) -> Pinger_Type {
        self.msg.get_message_type()
    }

    /// Get unique session number
    pub fn get_session(&self) -> Session {
        self.msg.get_session()
    }

    /// Get ping start ts
    pub fn get_start_timestamp(&self) -> Timestamp {
        self.msg.get_start_timestamp()
    }
}

impl Codec for PingerMsgDeprecated {
    const TYPES: &'static [PacketType] = &[PacketType::PingerDeprecated];

    fn decode(bytes: &[u8]) -> CodecResult<Self>
    where
        Self: Sized,
    {
        if bytes.is_empty() {
            return Err(CodecError::InvalidLength);
        }
        match PacketType::from(bytes[0]) {
            PacketType::PingerDeprecated => {
                if let Ok(peer_id) =
                    PeerId::try_from(bytes.get(1..3).ok_or(CodecError::InvalidLength)?)
                {
                    let pinger = Pinger::parse_from_bytes(&bytes[3..]);
                    return Ok(Self {
                        peer_id,
                        msg: pinger.map_err(|_| CodecError::DecodeFailed)?,
                    });
                }

                Err(CodecError::DecodeFailed)
            }
            _ => Err(CodecError::DecodeFailed),
        }
    }

    fn encode(self) -> CodecResult<Vec<u8>> {
        let mut bytes = Vec::with_capacity(MAX_PACKET_SIZE);

        bytes.put_u8(PacketType::PingerDeprecated as u8);
        bytes.put_u16(self.peer_id.0);
        self.msg
            .write_to_vec(&mut bytes)
            .map_err(|_| CodecError::Encode)?;

        Ok(bytes)
    }

    fn packet_type(&self) -> PacketType {
        PacketType::PingerDeprecated
    }
}

impl DowncastPacket for PingerMsgDeprecated {
    fn downcast(packet: Packet) -> Result<Self, Packet>
    where
        Self: Sized,
    {
        match packet {
            Packet::PingerDeprecated(data) => Ok(data),
            packet => Err(packet),
        }
    }
}

impl std::fmt::Display for PingerMsgDeprecated {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} peer_id: {}, session: {}, start_ts: {}",
            match self.get_message_type() {
                Pinger_Type::PING => "Ping: ",
                Pinger_Type::PONG => "Pong: ",
            },
            self.get_peer_id().0,
            self.get_session(),
            self.get_start_timestamp()
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fail_to_decode_small_packet() {
        let bytes = &[];
        let data = PingerMsg::decode(bytes);
        assert_eq!(data, Err(CodecError::InvalidLength));
    }

    #[test]
    fn fail_to_decode_packet_of_wrong_type() {
        let bytes = &[PacketType::Invalid as u8, 3, 1, 7, 6];
        let data = PingerMsg::decode(bytes);
        assert_eq!(data, Err(CodecError::DecodeFailed));
    }

    #[test]
    fn encode_packet() {
        let ping = PingerMsg::ping(WGPort(2), 3_u64, 10_u64);
        let ping_bytes = b"\x07\x00\x02\x10\x03\x18\x0A";
        assert_eq!(ping.encode().unwrap(), ping_bytes);

        let ping = PingerMsg::ping(WGPort(2), 3_u64, 10_u64);
        let pong = ping.pong(WGPort(3)).unwrap();
        let pong_bytes = b"\x07\x00\x03\x08\x01\x10\x03\x18\x0A";
        assert_eq!(pong.encode().unwrap(), pong_bytes);
    }

    #[test]
    fn deprecated_decode_packet() {
        let ping_bytes = &[4, 0, 8, 16, 9, 24, 128, 2];
        let ping_data = PingerMsgDeprecated::decode(ping_bytes).expect("Failed to parse packet");
        assert_eq!(ping_data.packet_type(), PacketType::PingerDeprecated);
        assert_eq!(ping_data.get_peer_id().0, 8_u16);
        assert_eq!(ping_data.get_session(), 9_u64);
        assert_eq!(ping_data.get_message_type(), Pinger_Type::PING);
        assert_eq!(ping_data.get_start_timestamp(), 256_u64);

        let pong_bytes = &[4, 0, 6, 8, 1, 16, 8, 24, 128, 4];
        let pong_data = PingerMsgDeprecated::decode(pong_bytes).expect("Failed to parse packet");
        assert_eq!(pong_data.packet_type(), PacketType::PingerDeprecated);
        assert_eq!(pong_data.get_peer_id().0, 6_u16);
        assert_eq!(pong_data.get_session(), 8_u64);
        assert_eq!(pong_data.get_start_timestamp(), 512_u64);
        assert_eq!(pong_data.get_message_type(), Pinger_Type::PONG);
    }

    #[test]
    fn deprecated_fail_to_decode_small_packet() {
        let bytes = &[];
        let data = PingerMsgDeprecated::decode(bytes);
        assert_eq!(data, Err(CodecError::InvalidLength));
    }

    #[test]
    fn deprecated_fail_to_decode_packet_of_wrong_type() {
        let bytes = &[PacketType::Invalid as u8, 3, 1, 7, 6];
        let data = PingerMsgDeprecated::decode(bytes);
        assert_eq!(data, Err(CodecError::DecodeFailed));
    }

    #[test]
    fn deprecated_encode_packet() {
        let ping = PingerMsgDeprecated::ping(PeerId(2), 3_u64, 10_u64);
        let ping_bytes = b"\x04\x00\x02\x10\x03\x18\x0A";
        assert_eq!(ping.encode().unwrap(), ping_bytes);

        let ping = PingerMsgDeprecated::ping(PeerId(2), 3_u64, 10_u64);
        let pong = ping.pong(PeerId(3)).unwrap();
        let pong_bytes = b"\x04\x00\x03\x08\x01\x10\x03\x18\x0A";
        assert_eq!(pong.encode().unwrap(), pong_bytes);
    }
}
