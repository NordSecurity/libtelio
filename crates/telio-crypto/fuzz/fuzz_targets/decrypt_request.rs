#![no_main]

use libfuzzer_sys::fuzz_target;
use once_cell::sync::Lazy;
use telio_crypto::{encryption::decrypt_request, SecretKey};

static LOCAL_SK: Lazy<SecretKey> = Lazy::new(SecretKey::gen);

fuzz_target!(|data: &[u8]| {
    println!("data: {:?}", data);
    decrypt_request(data, &*LOCAL_SK, |_| true);
});
