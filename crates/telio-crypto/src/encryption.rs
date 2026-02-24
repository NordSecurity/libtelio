//! This module contains helper functions for easier handling of encryption and decryption.

use std::{array::TryFromSliceError, convert::TryInto};

use telio_utils::telio_err_with_log;

use crate::{chachabox::ChaChaBox, PublicKey, SecretKey, KEY_SIZE};

const NONCE_SIZE: usize = 24;

/// Error returned when encrypting or decrypting.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Encryption failed
    #[error(transparent)]
    EncryptionFailed(#[from] aead::Error),
    /// Received request contained unknown key
    #[error("Request contains forbidden key: {0}")]
    ForbiddenKey(PublicKey),
    /// Not enough data in buffer when decrypting
    #[error("Invalid length when decrypting")]
    InvalidLength,
    /// Failure when converting to array
    #[error(transparent)]
    ArrayConversionError(#[from] TryFromSliceError),
}

/// Encrypt request stored in `msg`.
///
/// This function encrypts message from `msg` using `local_sk` as the secret key and `remote_pk` as
/// public key. It uses two layers of encryption so that the recipient can learn public key of sender
/// but at the same time public key of sender is not leaked in the output bytes. The `msg` is first
/// encrypted using `local_sk`, `remote_pk` and random `nonce1`. Next we prepend both public key
/// matching `local_sk` and `nonce1` to the encrypted `msg`. The result of prepend is used as input
/// message for outer/second layer of encryption. Outer layer uses randomly generated public/private key
/// pair and again `remote_pk`.
/// This ensures that owner of secret key matching `remote_pk` can decode outer layer and check attached
/// public key for inner layer. If they recognize that key decoding of inner layer can proceed.
pub fn encrypt_request(
    msg: &[u8],
    mut rng: &mut impl rand::CryptoRng,
    local_sk: &SecretKey,
    remote_pk: &PublicKey,
) -> Result<Vec<u8>, Error> {
    let inner_nonce = ChaChaBox::generate_nonce(&mut rng);
    let inner_secret_box = ChaChaBox::new(remote_pk, local_sk);
    let inner_encrypted_payload = match inner_secret_box.encrypt(&inner_nonce, msg) {
        Ok(inner_encrypted_payload) => inner_encrypted_payload,
        Err(e) => telio_err_with_log!(e)?,
    };

    let local_pk = &local_sk.public();

    let mut outer_msg =
        Vec::with_capacity(local_pk.len() + inner_nonce.len() + inner_encrypted_payload.len());
    outer_msg.extend_from_slice(local_pk);
    outer_msg.extend_from_slice(&inner_nonce);
    outer_msg.extend(inner_encrypted_payload);

    let ephemeral_sk = SecretKey::gen_with(rng);
    let ephemeral_pk = ephemeral_sk.public();
    let outer_nonce = ChaChaBox::generate_nonce(rng);
    let outer_secret_box = ChaChaBox::new(remote_pk, &ephemeral_sk);

    let outer_encrypted_payload = match outer_secret_box.encrypt(&outer_nonce, outer_msg.as_slice())
    {
        Ok(outer_encrypted_payload) => outer_encrypted_payload,
        Err(e) => telio_err_with_log!(e)?,
    };

    let mut complete_outer_payload =
        Vec::with_capacity(ephemeral_pk.len() + outer_nonce.len() + outer_encrypted_payload.len());
    complete_outer_payload.extend_from_slice(&ephemeral_pk);
    complete_outer_payload.extend_from_slice(&outer_nonce);
    complete_outer_payload.extend(outer_encrypted_payload);

    Ok(complete_outer_payload)
}

/// Decrypt request stored in `msg`.
///
/// This function should be used with payload created using `encrypt_request`.
pub fn decrypt_request(
    msg: &[u8],
    local_sk: &SecretKey,
    is_allowed: impl Fn(&PublicKey) -> bool,
) -> Result<(Vec<u8>, PublicKey), Error> {
    let ephemeral_pk: [u8; KEY_SIZE] = msg
        .get(..KEY_SIZE)
        .ok_or(Error::InvalidLength)?
        .try_into()?;
    let outer_nonce: [u8; NONCE_SIZE] = msg
        .get(KEY_SIZE..KEY_SIZE + NONCE_SIZE)
        .ok_or(Error::InvalidLength)?
        .try_into()?;
    let outer_encrypted_payload = msg
        .get(KEY_SIZE + NONCE_SIZE..)
        .ok_or(Error::InvalidLength)?;

    let outer_secret_box = ChaChaBox::new(&PublicKey(ephemeral_pk), local_sk);
    let outer_msg = match outer_secret_box.decrypt(&outer_nonce.into(), outer_encrypted_payload) {
        Ok(outer_msg) => outer_msg,
        Err(e) => telio_err_with_log!(e)?,
    };

    let remote_pk: [u8; KEY_SIZE] = outer_msg
        .get(..KEY_SIZE)
        .ok_or(Error::InvalidLength)?
        .try_into()?;
    let remote_pk = PublicKey(remote_pk);

    if !is_allowed(&remote_pk) {
        return Err(Error::ForbiddenKey(remote_pk));
    }

    let inner_nonce: [u8; NONCE_SIZE] = outer_msg
        .get(KEY_SIZE..KEY_SIZE + NONCE_SIZE)
        .ok_or(Error::InvalidLength)?
        .try_into()?;
    let inner_encrypted_payload = outer_msg
        .get(KEY_SIZE + NONCE_SIZE..)
        .ok_or(Error::InvalidLength)?;

    let inner_secret_box = ChaChaBox::new(&remote_pk, local_sk);
    let inner_msg = match inner_secret_box.decrypt(&inner_nonce.into(), inner_encrypted_payload) {
        Ok(inner_msg) => inner_msg,
        Err(e) => telio_err_with_log!(e)?,
    };

    Ok((inner_msg, remote_pk))
}

/// Encrypt message stored in `msg` using `local_sk` as secret key and `remote_pk` as public key.
///
/// Resulting payload contains in order: random nonce and encrypted message.
pub fn encrypt_response(
    msg: &[u8],
    rng: &mut impl rand::CryptoRng,
    local_sk: &SecretKey,
    remote_pk: &PublicKey,
) -> Result<Vec<u8>, Error> {
    let nonce = ChaChaBox::generate_nonce(rng);
    let secret_box = ChaChaBox::new(remote_pk, local_sk);
    let encrypted_msg = match secret_box.encrypt(&nonce, msg) {
        Ok(encrypted_msg) => encrypted_msg,
        Err(e) => telio_err_with_log!(e)?,
    };
    let mut complete_payload = Vec::with_capacity(nonce.len() + encrypted_msg.len());
    complete_payload.extend_from_slice(&nonce);
    complete_payload.extend(encrypted_msg);
    Ok(complete_payload)
}

/// Decrypt response stored in `msg`.
///
/// This function should be used with payload created using `encrypt_response`.
pub fn decrypt_response(
    msg: &[u8],
    local_sk: &SecretKey,
    remote_pk: &PublicKey,
) -> Result<Vec<u8>, Error> {
    let nonce: [u8; NONCE_SIZE] = msg
        .get(..NONCE_SIZE)
        .ok_or(Error::InvalidLength)?
        .try_into()?;
    let message = msg.get(NONCE_SIZE..).ok_or(Error::InvalidLength)?;
    let secret_box = ChaChaBox::new(remote_pk, local_sk);
    let msg = match secret_box.decrypt(&nonce.into(), message) {
        Ok(msg) => msg,
        Err(e) => telio_err_with_log!(e)?,
    };

    Ok(msg)
}

#[cfg(test)]
mod tests {

    use super::*;
    use bstr::ByteSlice;
    use telio_utils::test::{CryptoStepRng, StepRng};

    const MSG: &[u8] = b"test message";

    #[test]
    fn encrypt_request_example() -> Result<(), Error> {
        let mut rng = CryptoStepRng(StepRng::new(0, 1));
        let local_sk = SecretKey::gen_with(&mut rng);
        let remote_sk = SecretKey::gen_with(&mut rng);
        let remote_pk = remote_sk.public();
        let encrypted_request = encrypt_request(MSG, &mut rng, &local_sk, &remote_pk)?;
        assert_eq!(
            encrypted_request,
            [
                120, 210, 175, 83, 170, 79, 164, 218, 140, 183, 89, 25, 19, 146, 107, 78, 131, 169,
                88, 115, 98, 156, 203, 156, 237, 131, 154, 233, 145, 52, 75, 22,
                /* nonce start */
                15, 0, 0, 0, 0, 0, 0, 0, 16, 0, 0, 0, 0, 0, 0, 0, 17, 0, 0, 0, 0, 0, 0, 0,
                /* nonce end */
                13, 14, 122, 150, 136, 50, 7, 159, 252, 188, 68, 85, 35, 90, 20, 178, 143, 47, 87,
                198, 229, 197, 26, 22, 153, 201, 160, 89, 56, 146, 114, 224, 85, 252, 203, 193, 51,
                35, 162, 104, 94, 166, 32, 174, 67, 164, 248, 198, 58, 179, 105, 172, 123, 130,
                146, 219, 210, 174, 18, 157, 255, 251, 104, 81, 129, 228, 85, 91, 157, 94, 124, 40,
                206, 15, 9, 75, 59, 22, 134, 41, 42, 2, 216, 78, 227, 125, 34, 71, 94, 61, 236,
                161, 52, 222, 127, 237, 133, 249, 32, 180
            ]
        );
        Ok(())
    }

    #[test]
    fn encrypt_response_example() -> Result<(), Error> {
        let mut rng = CryptoStepRng(StepRng::new(0, 1));
        let local_sk = SecretKey::gen_with(&mut rng);
        let remote_sk = SecretKey::gen_with(&mut rng);
        let remote_pk = remote_sk.public();
        let encrypted_request = encrypt_response(MSG, &mut rng, &local_sk, &remote_pk)?;
        assert_eq!(
            encrypted_request,
            [
                /* nonce start */
                8, 0, 0, 0, 0, 0, 0, 0, 9, 0, 0, 0, 0, 0, 0, 0, 10, 0, 0, 0, 0, 0, 0, 0,
                /* nonce end */
                181, 135, 152, 63, 39, 205, 236, 36, 96, 224, 114, 28, 30, 193, 226, 170, 111, 164,
                192, 33, 101, 255, 67, 150, 110, 106, 86, 55
            ]
        );
        Ok(())
    }

    #[test]
    fn correct_request_roundtrip() -> Result<(), Error> {
        let mut rng = rand::rng();
        let local_sk = SecretKey::gen();
        let remote_sk = SecretKey::gen();
        let remote_pk = remote_sk.public();
        let encrypted_request = encrypt_request(MSG, &mut rng, &local_sk, &remote_pk)?;

        assert!(!encrypted_request.contains_str(MSG));
        assert!(!encrypted_request.contains_str(&local_sk));
        assert!(!encrypted_request.contains_str(&local_sk.public()));
        assert!(!encrypted_request.contains_str(&remote_pk));

        let (decrypted_request, key) = decrypt_request(&encrypted_request, &remote_sk, |_| true)?;
        assert_eq!(local_sk.public(), key);
        assert_eq!(MSG, decrypted_request);
        Ok(())
    }

    #[test]
    fn request_roundtrip_with_unknown_key() -> Result<(), Error> {
        let mut rng = rand::rng();
        let local_sk = SecretKey::gen();
        let remote_sk = SecretKey::gen();
        let remote_pk = remote_sk.public();
        let encrypted_request = encrypt_request(MSG, &mut rng, &local_sk, &remote_pk)?;

        let decrypted_request = decrypt_request(&encrypted_request, &remote_sk, |_| false);
        assert!(decrypted_request.is_err());
        Ok(())
    }

    #[test]
    fn correct_response_roundtrip() -> Result<(), Error> {
        let mut rng = rand::rng();
        let local_sk = SecretKey::gen();
        let local_pk = local_sk.public();
        let remote_sk = SecretKey::gen();
        let remote_pk = remote_sk.public();
        let encrypted_response = encrypt_response(MSG, &mut rng, &local_sk, &remote_pk)?;

        assert!(!encrypted_response.contains_str(MSG));
        assert!(!encrypted_response.contains_str(&local_sk));
        assert!(!encrypted_response.contains_str(&local_sk.public()));
        assert!(!encrypted_response.contains_str(&remote_pk));

        let decrypted_response = decrypt_response(&encrypted_response, &remote_sk, &local_pk)?;
        assert_eq!(MSG, decrypted_response);
        Ok(())
    }
}
