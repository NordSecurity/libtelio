use crate::{
    messages::nurse::*, Codec, CodecError, CodecResult, DowncastPacket, PacketRelayed,
    PacketTypeRelayed, MAX_PACKET_SIZE,
};
use bytes::BufMut;
use protobuf::{Message, RepeatedField};

/// Meshnet heartbeat message.
/// ```rust
/// # use crate::telio_proto::{Codec,HeartbeatMessage, HeartbeatStatus, HeartbeatType, PacketTypeRelayed};
/// let bytes = &[
///     0x2, 0x8, 0x1, 0x12, 0x1, 0x45, 0x1a, 0xb, 0x66, 0x69, 0x6e, 0x67, 0x65, 0x72, 0x70,
///     0x72, 0x69, 0x6e, 0x74, 0x22, 0x0,
/// ];
/// let data = HeartbeatMessage::decode(bytes).expect("Failed to parse packet");
/// assert_eq!(data.packet_type(), PacketTypeRelayed::Heartbeat);
/// assert_eq!(data.get_message_type(), HeartbeatType::RESPONSE);
/// assert_eq!(data.get_meshnet_id(), &[0x45]);
/// assert_eq!(data.get_node_fingerprint(), "fingerprint");
/// assert_eq!(data.get_statuses(), &[HeartbeatStatus::new()]);
///
/// assert_eq!(bytes, data.encode().unwrap().as_slice());
/// ```
#[derive(Debug, PartialEq, Clone)]
pub struct HeartbeatMessage(Heartbeat);

impl HeartbeatMessage {
    /// Returns new request [`HeartbeatMessage`].
    pub fn request() -> Self {
        Self(Heartbeat {
            message_type: Heartbeat_Type::REQUEST,
            ..Default::default()
        })
    }

    /// Returns new response [`HeartbeatMessage`].
    pub fn response(
        meshnet_id: Vec<u8>,
        node_fingerprint: String,
        statuses: &[Heartbeat_Status],
        nat_type: Heartbeat_NatType,
    ) -> Self {
        Self(Heartbeat {
            message_type: Heartbeat_Type::RESPONSE,
            statuses: RepeatedField::from_slice(statuses),
            node_fingerprint,
            meshnet_id,
            nat_type,
            ..Default::default()
        })
    }

    /// Returns [`Heartbeat_Type`] of the message
    pub fn get_message_type(&self) -> Heartbeat_Type {
        self.0.get_message_type()
    }

    /// Returns the [`Heartbeat_Status`]'es slice of the message
    pub fn get_statuses(&self) -> &[Heartbeat_Status] {
        self.0.get_statuses()
    }

    /// Returns the Node Fingerprint of the message
    pub fn get_node_fingerprint(&self) -> &str {
        self.0.get_node_fingerprint()
    }

    /// Returns the Meshnet ID of the message
    pub fn get_meshnet_id(&self) -> &[u8] {
        self.0.get_meshnet_id()
    }

    /// Returns the Nat Type of the message
    pub fn get_nat_type(&self) -> Heartbeat_NatType {
        self.0.get_nat_type()
    }
}

impl Codec<PacketTypeRelayed> for HeartbeatMessage {
    const TYPES: &'static [PacketTypeRelayed] = &[PacketTypeRelayed::Heartbeat];

    fn decode(bytes: &[u8]) -> CodecResult<Self>
    where
        Self: Sized,
    {
        if bytes.is_empty() {
            return Err(CodecError::InvalidLength);
        }

        match PacketTypeRelayed::from(*bytes.first().unwrap_or(&(PacketTypeRelayed::Invalid as u8)))
        {
            PacketTypeRelayed::Heartbeat => {
                let heartbeat =
                    Heartbeat::parse_from_bytes(bytes.get(1..).ok_or(CodecError::DecodeFailed)?);
                Ok(Self(heartbeat.map_err(|_| CodecError::DecodeFailed)?))
            }
            _ => Err(CodecError::DecodeFailed),
        }
    }

    fn encode(self) -> CodecResult<Vec<u8>>
    where
        Self: Sized,
    {
        let mut bytes = Vec::with_capacity(MAX_PACKET_SIZE);

        bytes.put_u8(PacketTypeRelayed::Heartbeat as u8);
        self.0
            .write_to_vec(&mut bytes)
            .map_err(|_| CodecError::Encode)?;

        Ok(bytes)
    }

    fn packet_type(&self) -> PacketTypeRelayed {
        PacketTypeRelayed::Heartbeat
    }
}

impl DowncastPacket<PacketRelayed> for HeartbeatMessage {
    fn downcast(packet: PacketRelayed) -> Result<Self, PacketRelayed>
    where
        Self: Sized,
    {
        match packet {
            PacketRelayed::Heartbeat(msg) => Ok(msg),
            packet => Err(packet),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_empty_buffer() {
        assert_eq!(
            HeartbeatMessage::decode(&[]),
            Err(CodecError::InvalidLength),
        );
    }

    #[test]
    fn encode_message() {
        let meshnet_id = vec![69];
        let message = HeartbeatMessage::response(
            meshnet_id,
            "fingerprint".to_string(),
            &[Heartbeat_Status::new()],
            Heartbeat_NatType::UdpBlocked,
        );

        let bytes = &[
            0x2, 0x8, 0x1, 0x12, 0x1, 0x45, 0x1a, 0xb, 0x66, 0x69, 0x6e, 0x67, 0x65, 0x72, 0x70,
            0x72, 0x69, 0x6e, 0x74, 0x22, 0x0,
        ];

        assert_eq!(message.encode().unwrap(), bytes);
    }
}
