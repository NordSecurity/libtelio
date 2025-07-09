use crate::{
    messages::nurse::*, Codec, CodecError, CodecResult, DowncastPacket, HeartbeatNatType,
    HeartbeatStatus, HeartbeatType, PacketRelayed, PacketTypeRelayed, MAX_PACKET_SIZE,
};
use bytes::BufMut;
use protobuf::Message;

/// Meshnet heartbeat message.
/// ```rust
/// # use crate::telio_proto::{Codec,HeartbeatMessage, HeartbeatStatus, HeartbeatType, PacketTypeRelayed};
/// let bytes = &[
///     0x2, 0x8, 0x1, 0x12, 0x1, 0x45, 0x1a, 0xb, 0x66, 0x69, 0x6e, 0x67, 0x65, 0x72, 0x70,
///     0x72, 0x69, 0x6e, 0x74, 0x22, 0x0,
/// ];
/// let data = HeartbeatMessage::decode(bytes).expect("Failed to parse packet");
/// assert_eq!(data.packet_type(), PacketTypeRelayed::Heartbeat);
/// assert_eq!(data.get_message_type().unwrap(), HeartbeatType::RESPONSE);
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
            message_type: heartbeat::Type::REQUEST.into(),
            ..Default::default()
        })
    }

    /// Returns new response [`HeartbeatMessage`].
    pub fn response(
        meshnet_id: Vec<u8>,
        node_fingerprint: String,
        statuses: &[heartbeat::Status],
    ) -> Self {
        Self(Heartbeat {
            message_type: heartbeat::Type::RESPONSE.into(),
            statuses: statuses.into(),
            node_fingerprint,
            meshnet_id,
            nat_type: HeartbeatNatType::Unknown.into(),
            ..Default::default()
        })
    }

    /// Returns [`Heartbeat_Type`] of the message
    pub fn get_message_type(&self) -> CodecResult<HeartbeatType> {
        self.0
            .message_type
            .enum_value()
            .map_err(|_| CodecError::DecodeFailed)
    }

    /// Returns the [`Heartbeat_Status`]'es slice of the message
    pub fn get_statuses(&self) -> &[HeartbeatStatus] {
        &self.0.statuses
    }

    /// Returns the Node Fingerprint of the message
    pub fn get_node_fingerprint(&self) -> &str {
        &self.0.node_fingerprint
    }

    /// Returns the Meshnet ID of the message
    pub fn get_meshnet_id(&self) -> &[u8] {
        &self.0.meshnet_id
    }

    /// Returns the Nat Type of the message
    pub fn get_nat_type(&self) -> CodecResult<HeartbeatNatType> {
        self.0
            .nat_type
            .enum_value()
            .map_err(|_| CodecError::DecodeFailed)
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
            &[HeartbeatStatus::new()],
        );

        let bytes = &[
            0x2, 0x8, 0x1, 0x12, 0x1, 0x45, 0x1a, 0xb, 0x66, 0x69, 0x6e, 0x67, 0x65, 0x72, 0x70,
            0x72, 0x69, 0x6e, 0x74, 0x22, 0x0, 0x28, 0x8,
        ];

        assert_eq!(message.encode().unwrap(), bytes);
    }
}
