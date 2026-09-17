#![no_main]

use crypto_box::{aead::Aead, aead::AeadCore};
use libfuzzer_sys::fuzz_target;
use once_cell::sync::Lazy;
use telio_crypto::{chachabox::ChaChaBox, encryption::decrypt_request, PublicKey, SecretKey};

static REMOTE_SK: Lazy<SecretKey> = Lazy::new(SecretKey::gen);
static EPHEMERAL_SK: Lazy<SecretKey> = Lazy::new(SecretKey::gen);
static EPHEMERAL_PK: Lazy<PublicKey> = Lazy::new(|| EPHEMERAL_SK.public());
static OUTER_NONCE: Lazy<[u8; 24]> =
    Lazy::new(|| ChaChaBox::generate_nonce(&mut rand::rng()).into());
static SECRET_BOX: Lazy<ChaChaBox> =
    Lazy::new(|| ChaChaBox::new(&REMOTE_SK.public(), &(*EPHEMERAL_SK)));

fuzz_target!(|data: &[u8]| {
    // This tests simulates case where attacker correctly generates random keys and applies outer layer
    // of encryption. We verify that we don't panic ragardless of what inner payload hides under outer
    // layer of encryption.

    let outer_encrypted_payload = SECRET_BOX.encrypt(&(*OUTER_NONCE).into(), data).unwrap();
    let mut complete_outer_payload =
        Vec::with_capacity(EPHEMERAL_PK.len() + OUTER_NONCE.len() + outer_encrypted_payload.len());
    complete_outer_payload.extend_from_slice(&*EPHEMERAL_PK);
    complete_outer_payload.extend_from_slice(&*OUTER_NONCE);
    complete_outer_payload.extend(outer_encrypted_payload);

    decrypt_request(&complete_outer_payload, &*REMOTE_SK, |_| true);
});
