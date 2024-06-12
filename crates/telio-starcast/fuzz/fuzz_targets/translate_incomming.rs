#![no_main]

use libfuzzer_sys::fuzz_target;
use telio_starcast::nat::{Nat, StarcastNat};

fuzz_target!(|data: &[u8]| {
    let mut nat = StarcastNat::new(
        "1.2.3.4".parse().unwrap(),
        "1:2::3:4".parse().unwrap(),
    );
    let mut packet = data.to_vec();
    let _ = nat.translate_incomming(&mut packet);
});
