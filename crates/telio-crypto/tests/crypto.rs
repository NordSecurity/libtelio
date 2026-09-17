use std::sync::LazyLock;
use telio_crypto::{PresharedKey, SecretKey};

static SK: LazyLock<SecretKey> = LazyLock::new(|| SecretKey::new([0xBAu8; 32]));
static PSK: LazyLock<PresharedKey> = LazyLock::new(|| PresharedKey::new([0xBAu8; 32]));

#[ignore]
#[test]
fn secret_key_printing() {
    // Not marking this whole test as only for release mode, since this can lead to us
    // running it in debug and getting no failure. This way if you see this test run on
    // CI (and pass), you know that it was run in the release mode.
    #[cfg(debug_assertions)]
    panic!("This test makes no sense in the debug mode, only run it in release mode");
    assert_eq!("SecretKey(****)", format!("{:?}", *SK));
    assert_eq!("PresharedKey(****)", format!("{:?}", *PSK));
}
