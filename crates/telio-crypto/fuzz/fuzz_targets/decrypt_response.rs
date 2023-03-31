#![no_main]

use libfuzzer_sys::fuzz_target;
use once_cell::sync::Lazy;
use telio_crypto::{encryption::decrypt_response, PublicKey, SecretKey};

static LOCAL_SK: Lazy<SecretKey> = Lazy::new(SecretKey::gen);
static REMOTE_SK: Lazy<SecretKey> = Lazy::new(SecretKey::gen);
static REMOTE_PK: Lazy<PublicKey> = Lazy::new(|| REMOTE_SK.public());

fuzz_target!(|data: &[u8]| {
    decrypt_response(data, &*LOCAL_SK, &*REMOTE_PK);
});
