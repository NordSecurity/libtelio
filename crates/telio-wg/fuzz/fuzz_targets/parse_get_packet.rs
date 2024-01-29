#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _result = telio_wg::pq::parse_get_response_fuzz(data);
});
