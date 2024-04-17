use std::iter::FromIterator;
use std::net::SocketAddr;

use crate::{
    messages::natter::*, Codec, CodecError, CodecResult, DowncastPacket, PacketRelayed,
    PacketTypeRelayed, PeerId, Session, MAX_PACKET_SIZE,
};
use bytes::BufMut;
use protobuf::{Message, RepeatedField};
use telio_utils::Hidden;

/// Packet encapsulating containing WG packets
/// ```rust
/// # use telio_proto::{CallMeMaybeMsg, Codec, PacketTypeRelayed};
/// let bytes = &[
///     6, 8, 1, 18, 13, 49, 48, 46, 48, 46, 48, 46, 49, 53, 58, 52, 52, 51, 33, 1, 0,
///     0, 0, 0, 0, 0, 0, 24, 1,
/// ];
/// let data = CallMeMaybeMsg::decode(bytes).expect("Failed to parse packet");
/// assert_eq!(data.packet_type(), PacketTypeRelayed::CallMeMaybe);
/// assert_eq!(data.get_session(), 1);
/// assert_eq!(data.get_addrs()[0], "10.0.0.15:443".parse().unwrap());
///
/// assert_eq!(bytes, data.encode().unwrap().as_slice());
/// ```
#[derive(Debug, PartialEq, Clone)]
pub struct CallMeMaybeMsg(CallMeMaybe);

impl CallMeMaybeMsg {
    /// Returns new msg [`CallMeMaybeMsg`].
    pub fn new<T: Iterator<Item = SocketAddr>>(
        initiator: bool,
        addrs: T,
        session: Session,
    ) -> Self {
        Self(CallMeMaybe {
            i_am: if initiator {
                CallMeMaybe_Type::INITIATOR
            } else {
                CallMeMaybe_Type::RESPONDER
            },
            my_addresses: RepeatedField::from_vec(
                addrs.into_iter().map(|addr| addr.to_string()).collect(),
            ),
            session,
            ..Default::default()
        })
    }

    /// Get list of endpoints
    pub fn get_addrs(&self) -> Vec<SocketAddr> {
        self.0
            .my_addresses
            .to_vec()
            .iter()
            .flat_map(|s| s.parse())
            .collect()
    }

    /// Returns [`CallMeMaybe_Type`] of the message
    pub fn get_message_type(&self) -> CallMeMaybe_Type {
        self.0.get_i_am()
    }

    /// Get unique session number
    pub fn get_session(&self) -> u64 {
        self.0.get_session()
    }
}

impl Codec<PacketTypeRelayed> for CallMeMaybeMsg {
    const TYPES: &'static [PacketTypeRelayed] = &[PacketTypeRelayed::CallMeMaybe];

    fn decode(bytes: &[u8]) -> CodecResult<Self>
    where
        Self: Sized,
    {
        if bytes.is_empty() {
            return Err(CodecError::InvalidLength);
        }
        match PacketTypeRelayed::from(*bytes.first().unwrap_or(&(PacketTypeRelayed::Invalid as u8)))
        {
            PacketTypeRelayed::CallMeMaybe => {
                let cmm =
                    CallMeMaybe::parse_from_bytes(bytes.get(1..).ok_or(CodecError::DecodeFailed)?);
                Ok(Self(cmm.map_err(|_| CodecError::DecodeFailed)?))
            }
            _ => Err(CodecError::DecodeFailed),
        }
    }

    fn encode(self) -> CodecResult<Vec<u8>>
    where
        Self: Sized,
    {
        let mut bytes = Vec::with_capacity(MAX_PACKET_SIZE);

        bytes.put_u8(PacketTypeRelayed::CallMeMaybe as u8);
        self.0
            .write_to_vec(&mut bytes)
            .map_err(|_| CodecError::Encode)?;

        Ok(bytes)
    }

    fn packet_type(&self) -> PacketTypeRelayed {
        PacketTypeRelayed::CallMeMaybe
    }
}

impl DowncastPacket<PacketRelayed> for CallMeMaybeMsg {
    fn downcast(packet: PacketRelayed) -> Result<Self, PacketRelayed>
    where
        Self: Sized,
    {
        match packet {
            PacketRelayed::CallMeMaybe(msg) => Ok(msg),
            packet => Err(packet),
        }
    }
}

impl std::fmt::Display for CallMeMaybeMsg {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "CallMeMaybe: i-am: {}, heres-my-number: {:?}, session: {}",
            match self.0.i_am {
                CallMeMaybe_Type::INITIATOR => "initiator",
                CallMeMaybe_Type::RESPONDER => "responder",
            },
            self.0.my_addresses,
            self.0.session,
        )
    }
}

/// Packet encapsulating containing WG packets
#[derive(Debug, PartialEq, Clone)]
pub struct CallMeMaybeMsgDeprecated(CallMeMaybeDeprecated);

impl CallMeMaybeMsgDeprecated {
    /// Returns new msg [`CallMeMaybeMsgDeprecated`].
    pub fn new<T: Iterator<Item = Hidden<SocketAddr>>>(
        initiator: bool,
        addrs: T,
        session: Session,
        peer_id: PeerId,
    ) -> Self {
        Self(CallMeMaybeDeprecated {
            i_am: if initiator {
                CallMeMaybeDeprecated_Type::INITIATOR
            } else {
                CallMeMaybeDeprecated_Type::RESPONDER
            },
            my_addresses: RepeatedField::from_iter(
                addrs.into_iter().map(|addr| addr.0.to_string()),
            ),
            my_peer_id: peer_id.0 as u32,
            session,
            ..Default::default()
        })
    }

    /// Get list of endpoints
    pub fn get_addrs(&self) -> Vec<Hidden<SocketAddr>> {
        self.0
            .my_addresses
            .to_vec()
            .iter()
            .flat_map(|s| s.parse())
            .map(Hidden)
            .collect()
    }

    /// Returns [`CallMeMaybe_Type`] of the message
    pub fn get_message_type(&self) -> CallMeMaybeDeprecated_Type {
        self.0.get_i_am()
    }

    /// Get peer id
    pub fn get_peer_id(&self) -> PeerId {
        PeerId(self.0.get_my_peer_id() as u16)
    }

    /// Get unique session number
    pub fn get_session(&self) -> u64 {
        self.0.get_session()
    }
}

impl Codec<PacketTypeRelayed> for CallMeMaybeMsgDeprecated {
    const TYPES: &'static [PacketTypeRelayed] = &[PacketTypeRelayed::CallMeMaybeDeprecated];

    fn decode(bytes: &[u8]) -> CodecResult<Self>
    where
        Self: Sized,
    {
        if bytes.is_empty() {
            return Err(CodecError::InvalidLength);
        }
        match PacketTypeRelayed::from(*bytes.first().unwrap_or(&(PacketTypeRelayed::Invalid as u8)))
        {
            PacketTypeRelayed::CallMeMaybeDeprecated => {
                let cmm = CallMeMaybeDeprecated::parse_from_bytes(
                    bytes.get(1..).ok_or(CodecError::DecodeFailed)?,
                );
                Ok(Self(cmm.map_err(|_| CodecError::DecodeFailed)?))
            }
            _ => Err(CodecError::DecodeFailed),
        }
    }

    fn encode(self) -> CodecResult<Vec<u8>>
    where
        Self: Sized,
    {
        let mut bytes = Vec::with_capacity(MAX_PACKET_SIZE);

        bytes.put_u8(PacketTypeRelayed::CallMeMaybeDeprecated as u8);
        self.0
            .write_to_vec(&mut bytes)
            .map_err(|_| CodecError::Encode)?;

        Ok(bytes)
    }

    fn packet_type(&self) -> PacketTypeRelayed {
        PacketTypeRelayed::CallMeMaybeDeprecated
    }
}

impl DowncastPacket<PacketRelayed> for CallMeMaybeMsgDeprecated {
    fn downcast(packet: PacketRelayed) -> Result<Self, PacketRelayed>
    where
        Self: Sized,
    {
        match packet {
            PacketRelayed::CallMeMaybeDeprecated(msg) => Ok(msg),
            packet => Err(packet),
        }
    }
}

impl std::fmt::Display for CallMeMaybeMsgDeprecated {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "CallMeMaybeDeprecated: i-am: {}, heres-my-number: {:?}, peer-id: {}, session: {}",
            match self.0.i_am {
                CallMeMaybeDeprecated_Type::INITIATOR => "initiator",
                CallMeMaybeDeprecated_Type::RESPONDER => "responder",
            },
            self.0.my_addresses,
            self.0.my_peer_id,
            self.0.session,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fail_to_decode_small_packet() {
        let bytes = &[];
        let data = CallMeMaybeMsg::decode(bytes);
        assert_eq!(data, Err(CodecError::InvalidLength));
    }

    #[test]
    fn fail_to_decode_packet_of_wrong_type() {
        let bytes = &[PacketTypeRelayed::Invalid as u8, 3, 1, 6, 7];
        let data = CallMeMaybeMsg::decode(bytes);
        assert_eq!(data, Err(CodecError::DecodeFailed));
    }

    #[test]
    fn encode_packet() {
        let packet = CallMeMaybeMsg::new(
            false,
            vec!["192.168.1.1:80".parse().unwrap()].into_iter(),
            1,
        );
        let bytes = &[
            6, 8, 1, 18, 14, 49, 57, 50, 46, 49, 54, 56, 46, 49, 46, 49, 58, 56, 48, 33, 1, 0, 0,
            0, 0, 0, 0, 0,
        ];
        assert_eq!(packet.encode().unwrap(), bytes)
    }

    #[test]
    fn deprecated_decode_packet() {
        let bytes = &[
            3, 8, 1, 18, 13, 49, 48, 46, 48, 46, 48, 46, 49, 53, 58, 52, 52, 51, 24, 1, 33, 1, 0,
            0, 0, 0, 0, 0, 0,
        ];
        let data = CallMeMaybeMsgDeprecated::decode(bytes).expect("Failed to parse packet");
        assert_eq!(data.packet_type(), PacketTypeRelayed::CallMeMaybeDeprecated);
        assert_eq!(data.get_session(), 1);
        assert_eq!(data.get_peer_id().0, 1);
        assert_eq!(
            data.get_addrs()[0],
            "10.0.0.15:443".parse::<SocketAddr>().unwrap()
        );
    }

    #[test]
    fn deprecated_fail_to_decode_small_packet() {
        let bytes = &[];
        let data = CallMeMaybeMsgDeprecated::decode(bytes);
        assert_eq!(data, Err(CodecError::InvalidLength));
    }

    #[test]
    fn deprecated_fail_to_decode_packet_of_wrong_type() {
        let bytes = &[PacketTypeRelayed::Invalid as u8, 3, 1, 6, 7];
        let data = CallMeMaybeMsgDeprecated::decode(bytes);
        assert_eq!(data, Err(CodecError::DecodeFailed));
    }

    #[test]
    fn deprecated_encode_packet() {
        let packet = CallMeMaybeMsgDeprecated::new(
            false,
            vec!["192.168.1.1:80".parse().unwrap()].into_iter(),
            1,
            PeerId(1),
        );
        let bytes = &[
            3, 8, 1, 18, 14, 49, 57, 50, 46, 49, 54, 56, 46, 49, 46, 49, 58, 56, 48, 24, 1, 33, 1,
            0, 0, 0, 0, 0, 0, 0,
        ];
        assert_eq!(packet.encode().unwrap(), bytes)
    }
}
