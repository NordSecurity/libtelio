#![deny(missing_docs)]

//! Common crypto primitives.
//!
//! This crate should be used when any crate needs to work with Secret and Public keys.
//!
//! SecretKey and PublicKey are from [Eliptic Curve 25519][ec] cryptography.
//!
//! [ec]: https://en.wikipedia.org/wiki/Curve25519
//!
//! ```
//! # use telio_crypto::{KeyDecodeError, SecretKey};
//! # fn main() -> Result<(), KeyDecodeError> {
//! const HEX_INPUT: &str = "babababababababababababababababababababababababababababababababa";
//! const BASE64_INPUT: &str = "urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6uro=";
//! let secret_key_a : SecretKey = HEX_INPUT.parse()?;
//! let secret_key_b : SecretKey = BASE64_INPUT.parse()?;
//! assert_eq!(secret_key_a, secret_key_b);
//! # Ok(())
//! # }
//! ```

pub mod encryption;

use std::{convert::TryInto, fmt};

use rand::prelude::*;
use serde_with::{DeserializeFromStr, SerializeDisplay};

/// Secret/Public key size in bytes
pub const KEY_SIZE: usize = 32;

/// Secret key type
#[derive(
    Default, PartialOrd, Ord, PartialEq, Eq, Hash, Copy, Clone, DeserializeFromStr, SerializeDisplay,
)]
pub struct SecretKey([u8; KEY_SIZE]);

/// Public key type
#[derive(
    Default, PartialOrd, Ord, PartialEq, Eq, Hash, Copy, Clone, DeserializeFromStr, SerializeDisplay,
)]
pub struct PublicKey(pub [u8; KEY_SIZE]);

/// Error returned when parsing fails for SecretKey or PublicKey.
#[derive(Debug, thiserror::Error)]
pub enum KeyDecodeError {
    /// String was not of valid length for hex(64 bytes) or base64(44 bytes) parsing.
    #[error("Invalid length for parsing [{0}], 64-hex, 44-base64")]
    InvalidLength(usize),
    /// String was not valid for base64 decoding.
    #[error(transparent)]
    Base64(#[from] base64::DecodeError),
    /// String was not valid for hex decoding.
    #[error(transparent)]
    Hex(#[from] hex::FromHexError),
}

impl SecretKey {
    /// Create new key from bytes
    /// This ensures bytes are properly clamped
    #[allow(index_access_check)]
    pub const fn new(mut bytes: [u8; KEY_SIZE]) -> Self {
        bytes[0] &= 248;
        bytes[31] &= 127;
        bytes[31] |= 64;

        Self(bytes)
    }

    /// Generates a new random SecretKey.
    /// # Examples
    ///
    /// ```
    /// # use telio_crypto::SecretKey;
    /// let secret_key_a = SecretKey::gen();
    /// let secret_key_b = SecretKey::gen();
    /// assert_ne!(secret_key_a, secret_key_b);
    /// ```
    pub fn gen() -> Self {
        Self::gen_with(&mut rand::rngs::StdRng::from_entropy())
    }

    pub(crate) fn gen_with(rng: &mut (impl RngCore + CryptoRng)) -> Self {
        let mut key = SecretKey([0u8; KEY_SIZE]);
        rng.fill_bytes(&mut key.0);
        // Key clamping
        if let Some(first) = key.first_mut() {
            *first &= 248;
        }
        if let Some(last) = key.last_mut() {
            *last &= 127;
            *last |= 64;
        }
        key
    }

    /// Calculates the corresponding PublicKey.
    /// # Examples
    ///
    /// ```
    /// # use telio_crypto::SecretKey;
    /// # let secret_key_a = SecretKey::gen();
    /// # let secret_key_b = SecretKey::gen();
    /// let pub_key_a = secret_key_a.public();
    /// let pub_key_b = secret_key_b.public();
    /// assert_ne!(pub_key_a, pub_key_b);
    /// ```
    pub fn public(&self) -> PublicKey {
        crypto_box::SecretKey::from(self.0).public_key().into()
    }

    /// Return key represented as bytes
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Convert secret key to raw bytes
    pub fn into_bytes(self) -> [u8; 32] {
        self.0
    }
}

impl PublicKey {
    /// Create new key from bytes
    pub const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

impl From<crypto_box::SecretKey> for SecretKey {
    fn from(sk: crypto_box::SecretKey) -> Self {
        Self(*sk.as_bytes())
    }
}

impl From<&crypto_box::SecretKey> for SecretKey {
    fn from(sk: &crypto_box::SecretKey) -> Self {
        Self(*sk.as_bytes())
    }
}

impl From<&SecretKey> for crypto_box::SecretKey {
    fn from(sk: &SecretKey) -> Self {
        Self::from(sk.0)
    }
}

impl From<SecretKey> for crypto_box::SecretKey {
    fn from(sk: SecretKey) -> Self {
        Self::from(sk.0)
    }
}

impl From<&[u8; crypto_box::KEY_SIZE]> for PublicKey {
    fn from(pk: &[u8; crypto_box::KEY_SIZE]) -> Self {
        Self(*pk)
    }
}

impl From<crypto_box::PublicKey> for PublicKey {
    fn from(pk: crypto_box::PublicKey) -> Self {
        Self(*pk.as_bytes())
    }
}

impl From<&crypto_box::PublicKey> for PublicKey {
    fn from(pk: &crypto_box::PublicKey) -> Self {
        Self(*pk.as_bytes())
    }
}

impl From<&PublicKey> for crypto_box::PublicKey {
    fn from(sk: &PublicKey) -> Self {
        Self::from(sk.0)
    }
}

impl From<PublicKey> for crypto_box::PublicKey {
    fn from(sk: PublicKey) -> Self {
        Self::from(sk.0)
    }
}

impl From<&SecretKey> for PublicKey {
    fn from(sk: &SecretKey) -> Self {
        sk.public()
    }
}

macro_rules! gen_common {
    ($t:ty) => {
        impl std::ops::Deref for $t {
            type Target = [u8];

            fn deref(&self) -> &Self::Target {
                &self.0
            }
        }

        impl std::convert::AsRef<[u8]> for $t {
            fn as_ref(&self) -> &[u8] {
                &self.0
            }
        }

        impl std::ops::DerefMut for $t {
            fn deref_mut(&mut self) -> &mut Self::Target {
                &mut self.0
            }
        }

        impl std::convert::TryFrom<&'_ [u8]> for $t {
            type Error = std::array::TryFromSliceError;

            fn try_from(slice: &[u8]) -> Result<Self, Self::Error> {
                Ok(Self(slice.try_into()?))
            }
        }

        impl std::convert::TryFrom<Vec<u8>> for $t {
            type Error = Vec<u8>;

            fn try_from(v: Vec<u8>) -> Result<Self, Self::Error> {
                Ok(Self(v.try_into()?))
            }
        }

        impl std::str::FromStr for $t {
            type Err = KeyDecodeError;

            fn from_str(s: &str) -> Result<Self, Self::Err> {
                let mut key = [0; KEY_SIZE];

                match s.len() {
                    64 => { hex::decode_to_slice(s, &mut key)? }
                    44 => { base64::decode_config_slice(s, base64::STANDARD, &mut key)?; }
                    l => return Err(KeyDecodeError::InvalidLength(l)),
                }

                Ok(Self::new(key))
            }
        }

        impl fmt::Display for $t {
            fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
                let mut buf = [0u8; 44];
                base64::encode_config_slice(&self.0, base64::STANDARD, &mut buf);
                match std::str::from_utf8(&buf) {
                    Ok(buf) =>  f.write_str(&buf),
                    Err(_) => Err(fmt::Error)
                }
            }
        }

        impl fmt::LowerHex for $t {
            fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
                let mut buf = [0u8; 64]; // 2 * KEY_SIZE
                match hex::encode_to_slice(&self.0, &mut buf) {
                    Ok(_) => {
                        match std::str::from_utf8(&buf) {
                            Ok(buf) => f.write_str(&buf),
                            Err(_) => Err(fmt::Error)
                        }
                    },
                    Err(_) => Err(fmt::Error)
                }
            }
        }

        impl fmt::Debug for $t {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                let buf = base64::encode(&self.0);
                f.write_str(&format!("\"{:.*}...{}\"", 4, &buf, &buf.get((buf.len())-4..).ok_or(fmt::Error)?))
            }
        }

    };
    ($t:ty, $($tt:ty),+) => {
        gen_common!($t);
        gen_common!($($tt),+);
    };
}
gen_common!(SecretKey, PublicKey);

#[cfg(test)]
mod tests {
    use super::*;

    const SK: SecretKey = SecretKey::new([0xBAu8; 32]);
    const SK_HEX: &str = "b8babababababababababababababababababababababababababababababa7a";
    const SK_B64: &str = "uLq6urq6urq6urq6urq6urq6urq6urq6urq6urq6uno=";
    const SK_B64_SHORT: &str = "\"uLq6...uno=\"";
    const PK: PublicKey = PublicKey([
        124, 138, 97, 25, 210, 221, 193, 169, 240, 19, 235, 72, 147, 68, 8, 93, 67, 1, 26, 73, 54,
        36, 116, 129, 248, 12, 124, 44, 238, 225, 78, 53,
    ]);
    const PK_HEX: &str = "7c8a6119d2ddc1a9f013eb489344085d43011a4936247481f80c7c2ceee14e35";
    const PK_B64: &str = "fIphGdLdwanwE+tIk0QIXUMBGkk2JHSB+Ax8LO7hTjU=";
    const PK_B64_SHORT: &str = "\"fIph...TjU=\"";

    #[test]
    fn secret_key_is_clammped() {
        assert_eq!(SK.as_bytes()[0], 0xb8);
        assert_eq!(SK.as_bytes()[31], 0x7a);
    }

    #[test]
    fn convert_sk_to_pk() {
        assert_eq!(PK, SK.public());
    }

    #[test]
    fn convert_to_base64() {
        assert_eq!(SK_B64, &format!("{}", SK));
        assert_eq!(PK_B64, &format!("{}", PK));
        assert_eq!(SK_B64_SHORT, &format!("{:?}", SK));
        assert_eq!(PK_B64_SHORT, &format!("{:?}", PK));
    }

    #[test]
    fn convert_from_base64() {
        assert_eq!(SK, SK_B64.parse().unwrap());
        assert_eq!(PK, PK_B64.parse().unwrap());
    }

    #[test]
    fn convert_to_hex() {
        assert_eq!(SK_HEX, &format!("{:x}", SK));
        assert_eq!(PK_HEX, &format!("{:x}", PK));
    }

    #[test]
    fn convert_from_hex() {
        assert_eq!(SK, SK_HEX.parse().unwrap());
        assert_eq!(PK, PK_HEX.parse().unwrap());
    }
}
