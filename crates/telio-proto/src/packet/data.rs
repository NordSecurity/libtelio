use bytes::BufMut;
use std::convert::TryFrom;

use super::PeerId;
use crate::{
    Codec, CodecError, CodecResult, DowncastPacket, Generation, Packet, PacketType, MAX_PACKET_SIZE,
};

/// Packet encapsulating containing WG packets
/// Data: [ type: 0x00u8, payload: [u8]]
/// GenData: [ type: 0x01u8, generation: u8, peer_id: u16, payload: [u8]]
/// # Examples
/// Parsing Data packet:
/// ```rust
/// # use crate::telio_proto::{Codec,DataMsg,PacketType};
/// let bytes = &[0, 1, 2, 3, 4, 5];
/// let data = DataMsg::decode(bytes).expect("Failed to parse packet");
/// assert_eq!(data.packet_type(), PacketType::Data);
/// assert_eq!(data.get_generation(), None);
/// assert_eq!(data.get_payload(), &[1, 2, 3, 4, 5]);
///
/// assert_eq!(bytes, data.encode().unwrap().as_slice());
/// ```
/// Parsing GenData packet:
/// ```rust
/// # use crate::telio_proto::{Codec,DataMsg,Generation,PacketType,PeerId};
/// let bytes = &[1, 255, 0, 42, 1, 2, 3, 4, 5];
/// let data = DataMsg::decode(bytes).expect("Failed to parse packet");
/// assert_eq!(data.packet_type(), PacketType::GenData);
/// assert_eq!(data.get_generation(), Some(Generation(255)));
/// assert_eq!(data.get_peer_id(), Some(PeerId(42)));
/// assert_eq!(data.get_payload(), &[1, 2, 3, 4, 5]);
///
/// assert_eq!(bytes, data.encode().unwrap().as_slice());
/// ```
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct DataMsg {
    bytes: Vec<u8>,
}

impl DataMsg {
    /// Creates new plain data message.
    pub fn new(wg_data: &[u8]) -> Self {
        let mut bytes = Vec::with_capacity(MAX_PACKET_SIZE);

        bytes.put_u8(PacketType::Data as u8);
        bytes.put(wg_data);

        Self { bytes }
    }

    /// Creates new generational data message with generation byte and peer ID.
    pub fn with_generation(wg_data: &[u8], generation: Generation, peer_id: PeerId) -> Self {
        let mut bytes = Vec::with_capacity(MAX_PACKET_SIZE);

        bytes.put_u8(PacketType::GenData as u8);
        bytes.put_u8(generation.0);
        bytes.put_u16(peer_id.0);
        bytes.put(wg_data);

        Self { bytes }
    }

    /// Returns message generation if packet type is [`PacketType::GenData`].
    pub fn get_generation(&self) -> Option<Generation> {
        if self.packet_type() == PacketType::GenData {
            return Some(Generation(self.bytes[1]));
        }

        None
    }

    /// Returns peer ID if packet type is [`PacketType::GenData`].
    pub fn get_peer_id(&self) -> Option<PeerId> {
        if self.packet_type() == PacketType::GenData {
            return PeerId::try_from(&(self.bytes[2..4])).ok();
        }

        None
    }

    /// Returns payload data.
    pub fn get_payload(&self) -> &[u8] {
        let offset = match self.packet_type() {
            PacketType::GenData => 4,
            _ => 1,
        };

        &self.bytes[offset..]
    }

    /// Set peer generation, transforming [`PacketType::Data`] into [`PacketType::GenData`] if needed.
    pub fn set_generation(&mut self, generation: Generation) {
        self.convert_to_gen_data();
        self.bytes[1] = generation.0;
    }

    /// Sets peer ID if packet type is [`PacketType::GenData`].
    pub fn set_peer_id(&mut self, peer_id: PeerId) -> CodecResult<()> {
        if self.packet_type() == PacketType::GenData {
            let mut bytes = Vec::with_capacity(2);
            bytes.put_u16(peer_id.0);

            let _: Vec<_> = self.bytes.splice(2..4, bytes).collect();

            return Ok(());
        }

        Err(CodecError::InvalidType)
    }

    fn convert_to_gen_data(&mut self) {
        if let PacketType::Data = self.packet_type() {
            self.bytes.extend([0u8; 3]);
            self.bytes.rotate_right(3);
            self.bytes[..4].copy_from_slice(&[PacketType::GenData as u8, 0, 0, 0]);
        }
    }
}

impl Codec for DataMsg {
    const TYPES: &'static [PacketType] = &[PacketType::Data, PacketType::GenData];

    fn decode(bytes: &[u8]) -> CodecResult<Self>
    where
        Self: Sized,
    {
        if bytes.is_empty() {
            return Err(CodecError::InvalidLength);
        }
        match PacketType::from(bytes[0]) {
            PacketType::Data => Ok(Self::new(&bytes[1..])),
            PacketType::GenData => {
                if bytes.len() < 4 {
                    return Err(CodecError::InvalidLength);
                }

                Ok(Self::with_generation(
                    &bytes[4..],
                    Generation(bytes[1]),
                    PeerId::try_from(&bytes[2..4]).or(Err(CodecError::DecodeFailed))?,
                ))
            }
            _ => Err(CodecError::DecodeFailed),
        }
    }

    fn encode(self) -> CodecResult<Vec<u8>>
    where
        Self: Sized,
    {
        Ok(self.bytes)
    }

    /// Returns [`PacketType`] for message.
    fn packet_type(&self) -> PacketType {
        PacketType::from(self.bytes[0])
    }
}

impl DowncastPacket for DataMsg {
    fn downcast(packet: Packet) -> std::result::Result<Self, Packet>
    where
        Self: Sized,
    {
        match packet {
            Packet::Data(data) => Ok(data),
            packet => Err(packet),
        }
    }
}

impl std::fmt::Display for DataMsg {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match PacketType::from(self.bytes[0]) {
            PacketType::Data => {
                write!(f, "Data: payload len: {}", self.get_payload().len(),)
            }
            PacketType::GenData => {
                write!(
                    f,
                    "GenData: generation: {}, peer_id: {} payload len: {}",
                    self.get_generation().unwrap_or_default(),
                    self.get_peer_id().unwrap_or_default().0,
                    self.get_payload().len(),
                )
            }
            _ => Err(std::fmt::Error),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fail_to_decode_small_packet() {
        let data = DataMsg::decode(&[]);
        assert_eq!(data, Err(CodecError::InvalidLength));

        let data = DataMsg::decode(&[1]);
        assert_eq!(data, Err(CodecError::InvalidLength));
    }

    #[test]
    fn fail_to_decode_packet_of_wrong_type() {
        let bytes = &[PacketType::Invalid as u8, 3, 1];
        let data = DataMsg::decode(bytes);
        assert_eq!(data, Err(CodecError::DecodeFailed));
    }

    #[test]
    fn encode_packet() {
        let packet = DataMsg::new(b"namas");
        let bytes = b"\x00namas";
        assert_eq!(packet.encode().unwrap(), bytes)
    }

    #[test]
    fn encode_packet_with_generation() {
        let packet = DataMsg::with_generation(b"namas", Generation(127), PeerId(654));
        let bytes = b"\x01\x7F\x02\x8Enamas";
        assert_eq!(packet.encode().unwrap(), bytes)
    }

    #[test]
    fn update_peer_id() {
        let mut packet = DataMsg::with_generation(b"namas", Generation(127), PeerId(654));
        let bytes_before = b"\x01\x7F\x02\x8Enamas";
        assert_eq!(packet.clone().encode().unwrap(), bytes_before);
        packet.set_peer_id(PeerId(1055)).unwrap();
        let bytes_after = b"\x01\x7F\x04\x1Fnamas";
        assert_eq!(packet.encode().unwrap(), bytes_after);
    }

    #[test]
    fn set_generation() {
        let mut packet = DataMsg::new(b"simple");
        assert_eq!(packet.packet_type(), PacketType::Data);
        assert_eq!(packet.get_generation(), None);
        assert_eq!(packet.get_peer_id(), None);
        assert_eq!(packet.get_payload(), b"simple");

        packet.set_generation(Generation(1));
        assert_eq!(packet.packet_type(), PacketType::GenData);
        assert_eq!(packet.get_generation(), Some(Generation(1)));
        assert_eq!(packet.get_peer_id(), Some(PeerId(0)));
        assert_eq!(packet.get_payload(), b"simple");

        packet.set_generation(Generation(8));
        assert_eq!(packet.packet_type(), PacketType::GenData);
        assert_eq!(packet.get_generation(), Some(Generation(8)));
        assert_eq!(packet.get_peer_id(), Some(PeerId(0)));
        assert_eq!(packet.get_payload(), b"simple");
    }
}
