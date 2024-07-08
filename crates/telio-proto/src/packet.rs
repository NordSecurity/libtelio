mod control;
mod relayed;

use crate::{Codec, CodecError, CodecResult};
use telio_crypto::PublicKey;

pub use relayed::{
    data::DataMsg,
    generation::Generation,
    natter::CallMeMaybeMsg,
    natter::CallMeMaybeMsgDeprecated,
    nurse::HeartbeatMessage,
    pinger::PingerMsg,
    pinger::Timestamp,
    pinger::{PartialPongerMsg, PlaintextPongerMsg},
    upgrade::{Decision, UpgradeDecisionMsg, UpgradeMsg},
};

pub use control::derppoll::{DerpPollRequestMsg, DerpPollResponseMsg, PeersStatesMap};

use std::convert::TryFrom;

/// Default buffer capacity allocated for a packet
pub const MAX_PACKET_SIZE: usize = 65536;

/// Session number for pinger and natter messages
pub type Session = u64;

/// Unique id, generate from peer's public keys
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub struct PeerId(pub u16);

/// Unique id, generate from peer's public keys
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub struct WGPort(pub u16);

/// Downcast packet to a more concrete type
pub trait DowncastPacket<Packet> {
    /// Downcast packet into inner type or return enum on failure.
    fn downcast(packet: Packet) -> Result<Self, Packet>
    where
        Self: Sized;
}

/// Trait bound for any packet.
pub trait AnyPacket<Packet, PacketType: 'static>:
    Codec<PacketType> + DowncastPacket<Packet> + Into<Packet> + Send
{
}

impl<T, Packet, PacketType: 'static> AnyPacket<Packet, PacketType> for T where
    T: Codec<PacketType> + DowncastPacket<Packet> + Into<Packet> + Send
{
}

#[repr(u8)]
#[derive(Debug, Hash, PartialEq, Eq, Copy, Clone, strum::EnumIter, strum::FromRepr)]
/// Byte encoding of telio [PacketRelayed] types.
pub enum PacketTypeRelayed {
    /// Plain WG packet.
    Data = 0x00,
    /// Plain WG packet with generation index.
    GenData = 0x01,
    /// Meshnet heartbeat packet.
    Heartbeat = 0x02,
    /// CallMeMaybe messages from/to natter
    CallMeMaybeDeprecated = 0x03,

    /// PingerDeprecated = 0x04,

    /// Encrypted package which is not Data type
    Encrypted = 0x05,
    /// CallMeMaybe messages from/to natter
    CallMeMaybe = 0x06,
    /// Pinger packets (oneway, ping_latency, simple pings ...)
    Pinger = 0x07,
    /// Message used for requesting an WireGuard endpoint upgrade
    Upgrade = 0x08,
    /// Ponger packet
    Ponger = 0x09,

    /// Message with a reply for the Upgrade message
    UpgradeDecision = 0x0a,

    /// Reserved for future, in case we use all byte values for types.
    Reserved = 0xfe,

    /// Packet is of invalid type.
    Invalid = 0xff,
}

impl From<u8> for PacketTypeRelayed {
    fn from(val: u8) -> Self {
        PacketTypeRelayed::from_repr(val).unwrap_or(PacketTypeRelayed::Invalid)
    }
}

/// Packet for Node <-> Node communication.
#[derive(Debug, PartialEq, Clone)]
pub enum PacketRelayed {
    /// Packet used to transfer WG packets.
    Data(DataMsg),
    /// Meshnet heartbeat packet.
    Heartbeat(HeartbeatMessage),
    /// Deprecated for natter <--> natter communications
    CallMeMaybeDeprecated(CallMeMaybeMsgDeprecated),
    /// For natter <--> natter communications
    CallMeMaybe(CallMeMaybeMsg),
    /// Pinging and checking the remote endpoints
    Pinger(PingerMsg),
    /// Reply to the Pinger
    Ponger(PartialPongerMsg),
    /// Upgrading connection
    Upgrade(UpgradeMsg),
    /// Upgrading connection result
    UpgradeDecision(UpgradeDecisionMsg),
}

impl PacketRelayed {
    /// Decode and decrypt `bytes` using `decrypt` function.
    ///
    /// Some messages are sent (partialy) encrypted and in such cases decryption is needed. Otherwise
    /// this function bahaves just like `Codec::decode`.
    pub fn decode_and_decrypt(
        bytes: &[u8],
        decrypt: impl FnOnce(PacketTypeRelayed, &[u8]) -> CodecResult<(Vec<u8>, Option<PublicKey>)>,
    ) -> CodecResult<(Self, Option<PublicKey>)>
    where
        Self: Sized,
    {
        use PacketTypeRelayed::*;

        if bytes.is_empty() {
            return Err(CodecError::InvalidLength);
        }

        Ok((
            match PacketTypeRelayed::from(*bytes.first().unwrap_or(&(Invalid as u8))) {
                Data | GenData => Self::Data(DataMsg::decode(bytes)?),
                Heartbeat => Self::Heartbeat(HeartbeatMessage::decode(bytes)?),
                CallMeMaybe => Self::CallMeMaybe(CallMeMaybeMsg::decode(bytes)?),
                Pinger => {
                    let (msg, public_key) = PingerMsg::decode_and_decrypt(bytes, decrypt)?;
                    return Ok((Self::Pinger(msg), public_key));
                }
                Ponger => {
                    return Ok((
                        Self::Ponger(PartialPongerMsg::decode_and_decrypt(bytes, decrypt)?),
                        None,
                    ))
                }
                CallMeMaybeDeprecated => {
                    Self::CallMeMaybeDeprecated(CallMeMaybeMsgDeprecated::decode(bytes)?)
                }
                Upgrade => Self::Upgrade(UpgradeMsg::decode(bytes)?),
                UpgradeDecision => Self::UpgradeDecision(UpgradeDecisionMsg::decode(bytes)?),
                // At this point a package already should be decrypted if is not Data
                Reserved | Invalid | Encrypted => return Err(CodecError::DecodeFailed),
            },
            None,
        ))
    }
}

impl Codec<PacketTypeRelayed> for PacketRelayed {
    const TYPES: &'static [PacketTypeRelayed] = &[
        PacketTypeRelayed::Data,
        PacketTypeRelayed::GenData,
        PacketTypeRelayed::Heartbeat,
        PacketTypeRelayed::CallMeMaybeDeprecated,
        PacketTypeRelayed::CallMeMaybe,
        PacketTypeRelayed::Pinger,
        PacketTypeRelayed::Upgrade,
        PacketTypeRelayed::Ponger,
        PacketTypeRelayed::UpgradeDecision,
    ];

    fn decode(bytes: &[u8]) -> CodecResult<Self>
    where
        Self: Sized,
    {
        use PacketTypeRelayed::*;

        if bytes.is_empty() {
            return Err(CodecError::InvalidLength);
        }

        match PacketTypeRelayed::from(*bytes.first().unwrap_or(&(Invalid as u8))) {
            Data | GenData => Ok(Self::Data(DataMsg::decode(bytes)?)),
            Heartbeat => Ok(Self::Heartbeat(HeartbeatMessage::decode(bytes)?)),
            CallMeMaybe => Ok(Self::CallMeMaybe(CallMeMaybeMsg::decode(bytes)?)),
            Pinger => Ok(Self::Pinger(PingerMsg::decode(bytes)?)),
            Ponger => Ok(Self::Ponger(PartialPongerMsg::decode(bytes)?)),
            CallMeMaybeDeprecated => Ok(Self::CallMeMaybeDeprecated(
                CallMeMaybeMsgDeprecated::decode(bytes)?,
            )),
            Upgrade => Ok(Self::Upgrade(UpgradeMsg::decode(bytes)?)),
            UpgradeDecision => Ok(Self::UpgradeDecision(UpgradeDecisionMsg::decode(bytes)?)),
            // At this point a package already should be decrypted if is not Data
            Reserved | Invalid | Encrypted => Err(CodecError::DecodeFailed),
        }
    }
    // can be done with enum_dispatch
    fn encode(self) -> CodecResult<Vec<u8>> {
        match self {
            Self::Data(msg) => msg.encode(),
            Self::Heartbeat(msg) => msg.encode(),
            Self::CallMeMaybe(msg) => msg.encode(),
            Self::Pinger(msg) => msg.encode(),
            Self::Ponger(msg) => msg.encode(),
            Self::CallMeMaybeDeprecated(msg) => msg.encode(),
            Self::Upgrade(msg) => msg.encode(),
            Self::UpgradeDecision(msg) => msg.encode(),
        }
    }

    // can be done with enum_dispatch
    fn packet_type(&self) -> PacketTypeRelayed {
        match self {
            Self::Data(msg) => msg.packet_type(),
            Self::Heartbeat(msg) => msg.packet_type(),
            Self::CallMeMaybe(msg) => msg.packet_type(),
            Self::Pinger(msg) => msg.packet_type(),
            Self::Ponger(msg) => msg.packet_type(),
            Self::CallMeMaybeDeprecated(msg) => msg.packet_type(),
            Self::Upgrade(msg) => msg.packet_type(),
            Self::UpgradeDecision(msg) => msg.packet_type(),
        }
    }
}

#[repr(u8)]
#[derive(Debug, Hash, PartialEq, Eq, Copy, Clone, strum::EnumIter, strum::FromRepr)]
/// Byte encoding of telio [PacketControl] types.
pub enum PacketTypeControl {
    /// Polling derp for remote peer states
    DerpPollRequest = 0x00,
    /// Response to DerpPollRequest
    DerpPollResponse = 0x01,

    /// Reserved for future, in case we use all byte values for types.
    Reserved = 0xfe,

    /// Packet is of invalid type.
    Invalid = 0xff,
}

impl From<u8> for PacketTypeControl {
    fn from(val: u8) -> Self {
        PacketTypeControl::from_repr(val).unwrap_or(PacketTypeControl::Invalid)
    }
}

/// Packet for Node <-> Derp communication.
#[derive(Debug, PartialEq, Clone)]
// #[enum_dispatch]
pub enum PacketControl {
    /// Poll remote peer states
    DerpPollRequest(DerpPollRequestMsg),
    /// Reply to DerpPollRequest
    DerpPollResponse(DerpPollResponseMsg),
}

impl Codec<PacketTypeControl> for PacketControl {
    const TYPES: &'static [PacketTypeControl] = &[
        PacketTypeControl::DerpPollRequest,
        PacketTypeControl::DerpPollResponse,
    ];

    fn decode(bytes: &[u8]) -> CodecResult<Self>
    where
        Self: Sized,
    {
        use PacketTypeControl::*;

        if bytes.is_empty() {
            return Err(CodecError::InvalidLength);
        }

        match PacketTypeControl::from(*bytes.first().unwrap_or(&(Invalid as u8))) {
            DerpPollRequest => Ok(Self::DerpPollRequest(DerpPollRequestMsg::decode(bytes)?)),
            DerpPollResponse => Ok(Self::DerpPollResponse(DerpPollResponseMsg::decode(bytes)?)),
            Reserved | Invalid => Err(CodecError::DecodeFailed),
        }
    }

    fn encode(self) -> CodecResult<Vec<u8>> {
        match self {
            Self::DerpPollRequest(msg) => msg.encode(),
            Self::DerpPollResponse(msg) => msg.encode(),
        }
    }

    fn packet_type(&self) -> PacketTypeControl {
        match self {
            Self::DerpPollRequest(msg) => msg.packet_type(),
            Self::DerpPollResponse(msg) => msg.packet_type(),
        }
    }
}

impl TryFrom<&[u8]> for PeerId {
    type Error = CodecError;

    fn try_from(other: &[u8]) -> std::result::Result<Self, Self::Error> {
        if other.len() != std::mem::size_of::<PeerId>() {
            return Err(CodecError::DecodeFailed);
        }

        // Note: all data should be converted to network endian (BE)
        Ok(Self(u16::from_be_bytes([
            *other.first().ok_or(CodecError::DecodeFailed)?,
            *other.get(1).ok_or(CodecError::DecodeFailed)?,
        ])))
    }
}

impl TryFrom<&[u8]> for WGPort {
    type Error = CodecError;

    fn try_from(other: &[u8]) -> std::result::Result<Self, Self::Error> {
        if other.len() != std::mem::size_of::<WGPort>() {
            return Err(CodecError::DecodeFailed);
        }

        // Note: all data should be converted to network endian (BE)
        let other_le = [
            *other.first().ok_or(CodecError::DecodeFailed)?,
            *other.get(1).ok_or(CodecError::DecodeFailed)?,
        ];
        Ok(Self(u16::from_be_bytes(other_le)))
    }
}

impl From<DataMsg> for PacketRelayed {
    fn from(other: DataMsg) -> Self {
        Self::Data(other)
    }
}

impl From<CallMeMaybeMsg> for PacketRelayed {
    fn from(other: CallMeMaybeMsg) -> Self {
        Self::CallMeMaybe(other)
    }
}

impl From<CallMeMaybeMsgDeprecated> for PacketRelayed {
    fn from(other: CallMeMaybeMsgDeprecated) -> Self {
        Self::CallMeMaybeDeprecated(other)
    }
}

impl From<HeartbeatMessage> for PacketRelayed {
    fn from(other: HeartbeatMessage) -> Self {
        Self::Heartbeat(other)
    }
}

impl From<UpgradeMsg> for PacketRelayed {
    fn from(other: UpgradeMsg) -> Self {
        Self::Upgrade(other)
    }
}

impl From<PartialPongerMsg> for PacketRelayed {
    fn from(other: PartialPongerMsg) -> Self {
        Self::Ponger(other)
    }
}

impl From<UpgradeDecisionMsg> for PacketRelayed {
    fn from(other: UpgradeDecisionMsg) -> Self {
        Self::UpgradeDecision(other)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use strum::IntoEnumIterator;

    #[test]
    fn all_packet_types_are_covered() {
        let skip = [
            PacketTypeRelayed::Reserved,
            PacketTypeRelayed::Encrypted,
            PacketTypeRelayed::Invalid,
        ];
        assert_eq!(
            PacketRelayed::TYPES,
            &PacketTypeRelayed::iter()
                .filter(|pt| !skip.contains(pt))
                .collect::<Vec<_>>()
        );

        let skip = [PacketTypeControl::Reserved, PacketTypeControl::Invalid];
        assert_eq!(
            PacketControl::TYPES,
            &PacketTypeControl::iter()
                .filter(|pt| !skip.contains(pt))
                .collect::<Vec<_>>()
        )
    }

    #[test]
    fn decode_empty_packet() {
        assert_eq!(PacketRelayed::decode(&[]), Err(CodecError::InvalidLength));
        assert_eq!(PacketControl::decode(&[]), Err(CodecError::InvalidLength));
    }

    #[test]
    fn decode_invalid_packet() {
        let bytes = &[PacketTypeRelayed::Invalid as u8, 1, 2, 3];
        assert_eq!(PacketRelayed::decode(bytes), Err(CodecError::DecodeFailed));

        let bytes = &[PacketTypeControl::Invalid as u8, 1, 2, 3];
        assert_eq!(PacketControl::decode(bytes), Err(CodecError::DecodeFailed));
    }

    #[test]
    fn decode_data_packet() {
        let bytes = &[0, 1, 2, 3];
        let expected: PacketRelayed = DataMsg::new(&[1, 2, 3]).into();
        assert_eq!(PacketRelayed::decode(bytes), Ok(expected));
    }

    #[test]
    fn encode_data_packet() {
        let packet: PacketRelayed = DataMsg::new(&[3, 2, 1]).into();
        let expected = &[0, 3, 2, 1];
        assert_eq!(&packet.encode().unwrap(), expected);
    }
}
