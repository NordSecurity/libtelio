use thiserror::Error as ThisError;

use crate::PacketType;

/// Posible [Codec] trait errors.
#[derive(ThisError, Debug, PartialEq, Eq)]
pub enum Error {
    /// Length of bytes being parrsed is invalid.
    #[error("Bytes is of invalid length.")]
    InvalidLength,
    /// Encoder received malformed data.
    #[error("Message has invalid type")]
    InvalidType,
    /// Bytes format is invalid for deserialization.
    #[error("Failed to parse packet.")]
    DecodeFailed,
    /// Encoder received malformed data.
    #[error("Failed to encode message")]
    Encode,
    /// Encryption failed
    #[error("Encryption failed: {0}")]
    EncryptionFailed(String),
    /// Decryption failed
    #[error("Decryption failed: {0}")]
    DecryptionFailed(String),
}

/// Result wrapper for implementations.
pub type Result<T> = std::result::Result<T, Error>;

/// Common trait for packet encoding/decoding.
pub trait Codec {
    /// [PacketType]s convertable by the codec.
    const TYPES: &'static [PacketType];

    /// Decode on-wire packet to rust type.
    fn decode(bytes: &[u8]) -> Result<Self>
    where
        Self: Sized;

    /// Encode rust type to on-wire packet.
    fn encode(self) -> Result<Vec<u8>>
    where
        Self: Sized;

    /// Actual packet type of current packet.
    fn packet_type(&self) -> PacketType;
}
