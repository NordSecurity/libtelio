#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    println!("data: {:?}", data);
    let _result = telio_pq::fuzz::parse_get_response(data);
});
