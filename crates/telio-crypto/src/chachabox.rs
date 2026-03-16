//! The module contains a replacement of the crypto_box::ChaChaBox using XChaCha20 which was
//! removed from the new versions of the library.

use aead::{Aead, AeadCore, KeyInit, Payload};
use chacha20::{cipher::generic_array::GenericArray, hchacha};
use chacha20poly1305::consts::U10;
use chacha20poly1305::XChaCha20Poly1305;
use curve25519_dalek::{scalar::clamp_integer, MontgomeryPoint, Scalar};
use zeroize::Zeroizing;

use crate::{PublicKey, SecretKey};

/// Public-key encryption scheme based on the X25519 Elliptic Curve Diffie-Hellman function and
/// the [XChaCha20Poly1305] authenticated encryption cipher.
pub struct ChaChaBox(XChaCha20Poly1305);

type Nonce = GenericArray<u8, <XChaCha20Poly1305 as AeadCore>::NonceSize>;

impl AeadCore for ChaChaBox {
    type NonceSize = <XChaCha20Poly1305 as AeadCore>::NonceSize;

    type TagSize = <XChaCha20Poly1305 as AeadCore>::TagSize;

    type CiphertextOverhead = <XChaCha20Poly1305 as AeadCore>::CiphertextOverhead;
}

impl ChaChaBox {
    /// Create a ChaCha20 crypto box for given remote public key and local private key
    pub fn new(public_key: &PublicKey, secret_key: &SecretKey) -> Self {
        let scalar_sk = Scalar::from_bytes_mod_order(clamp_integer(secret_key.0 .0));
        let shared_secret = Zeroizing::new(scalar_sk * MontgomeryPoint(public_key.0));

        // Use HChaCha20 to create a uniformly random key from the shared secret
        Self(XChaCha20Poly1305::new(&hchacha::<U10>(
            GenericArray::from_slice(&shared_secret.0),
            &GenericArray::default(),
        )))
    }

    /// Generate a random nonce for use with XChaCha20Poly1305.
    ///
    /// Equivalent to `aead::AeadCore::generate_nonce` but uses `rand_core` 0.10
    /// to avoid a version mismatch with the `aead` crate's bundled `rand_core`.
    /// The implementation is identical: fill a zero-initialised nonce array with
    /// random bytes from a cryptographically-secure RNG.
    pub fn generate_nonce(mut rng: impl rand::CryptoRng) -> Nonce {
        let mut nonce = Nonce::default();
        rng.fill_bytes(&mut nonce);
        nonce
    }

    /// Encrypt the data for the given nonce
    pub fn encrypt<'msg, 'aad>(
        &self,
        nonce: &Nonce,
        plaintext: impl Into<Payload<'msg, 'aad>>,
    ) -> Result<Vec<u8>, aead::Error> {
        self.0.encrypt(nonce, plaintext)
    }

    /// Decrypt the data for the given nonce
    pub fn decrypt<'msg, 'aad>(
        &self,
        nonce: &Nonce,
        ciphertext: impl Into<Payload<'msg, 'aad>>,
    ) -> Result<Vec<u8>, aead::Error> {
        self.0.decrypt(nonce, ciphertext)
    }
}
