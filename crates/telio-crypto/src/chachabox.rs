//! The module contains a replacement of the crypto_box::ChaChaBox using XChaCha20 which was
//! removed from the new versions of the library.

use aead::{Aead, AeadCore, KeyInit, Payload};
use chacha20::{cipher::generic_array::GenericArray, hchacha};
use chacha20poly1305::consts::U10;
use chacha20poly1305::XChaCha20Poly1305;
use curve25519_dalek::{scalar::clamp_integer, MontgomeryPoint, Scalar};
use rand::{CryptoRng, RngCore};
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

    /// Generate nonce bytes
    pub fn generate_nonce(rng: impl CryptoRng + RngCore) -> Nonce {
        XChaCha20Poly1305::generate_nonce(rng)
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
