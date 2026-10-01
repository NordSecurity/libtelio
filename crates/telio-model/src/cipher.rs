//! AEAD cipher suite type for libtelio's VPN connection configuration.
//!
//! [`Cipher`] mirrors [`wireguard_uapi::xplatform::Cipher`] but is defined here so
//! that the public API surface does not expose wireguard-uapi as a direct dependency.

use std::fmt;
use std::str::FromStr;

use tracing::warn;

/// AEAD cipher suites.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Cipher {
    /// ChaCha20-Poly1305, the WireGuard default.
    Chacha20Poly1305,
    /// AEGIS-256 with a 256-bit tag.
    Aegis256,
    /// AEGIS-256 with two parallel instances.
    Aegis256x2,
    /// AEGIS-256 with four parallel instances.
    Aegis256x4,
}

impl fmt::Display for Cipher {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Cipher::Chacha20Poly1305 => "chacha20poly1305",
            Cipher::Aegis256 => "aegis256",
            Cipher::Aegis256x2 => "aegis256x2",
            Cipher::Aegis256x4 => "aegis256x4",
        })
    }
}

#[derive(Debug, PartialEq, Eq)]
/// Error returned when a cipher name string cannot be parsed into a [`Cipher`].
pub struct UnknownCipher(pub String);

impl fmt::Display for UnknownCipher {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "unknown cipher: `{}`", self.0)
    }
}

impl std::error::Error for UnknownCipher {}

impl FromStr for Cipher {
    type Err = UnknownCipher;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim() {
            "chacha20poly1305" => Ok(Cipher::Chacha20Poly1305),
            "aegis256" => Ok(Cipher::Aegis256),
            "aegis256x2" => Ok(Cipher::Aegis256x2),
            "aegis256x4" => Ok(Cipher::Aegis256x4),
            other => Err(UnknownCipher(other.to_string())),
        }
    }
}

/// Parse a comma-separated list of cipher names into a [`Vec<Cipher>`].
/// ```
/// use telio_model::cipher::parse_ciphers;
/// let ciphers = parse_ciphers("chacha20poly1305, aegis256, unknown".to_string());
/// // => [Cipher::Chacha20Poly1305, Cipher::Aegis256]
/// ```
pub fn parse_ciphers(ciphers: String) -> Vec<Cipher> {
    ciphers
        .split(',')
        .filter_map(|s| {
            let token = s.trim();
            match token.parse::<Cipher>() {
                Ok(cipher) => Some(cipher),
                Err(e) => {
                    warn!("Unsupported cipher ignored: {e}");
                    None
                }
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_and_from_str_round_trip() {
        let variants = [
            (Cipher::Chacha20Poly1305, "chacha20poly1305"),
            (Cipher::Aegis256, "aegis256"),
            (Cipher::Aegis256x2, "aegis256x2"),
            (Cipher::Aegis256x4, "aegis256x4"),
        ];
        for (cipher, wire) in &variants {
            assert_eq!(cipher.to_string(), *wire, "Display mismatch for {cipher:?}");
            assert_eq!(
                wire.parse::<Cipher>().unwrap(),
                *cipher,
                "FromStr mismatch for {wire}"
            );
        }
    }

    #[test]
    fn from_str_unknown_returns_err() {
        assert!("aes128gcm".parse::<Cipher>().is_err());
        assert!("".parse::<Cipher>().is_err());
        assert!("AEGIS256".parse::<Cipher>().is_err());
    }

    #[test]
    fn parse_ciphers_skips_unknown_tokens() {
        let result = parse_ciphers("chacha20poly1305, aegis256, unknown".to_string());
        assert_eq!(result, vec![Cipher::Chacha20Poly1305, Cipher::Aegis256]);
    }

    #[test]
    fn parse_ciphers_empty_string_returns_empty_vec() {
        assert!(parse_ciphers(String::new()).is_empty());
    }
}
