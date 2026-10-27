#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _result =
        telio_pq::fuzz::parse_get_response(data, 49152, 1, telio_pq::fuzz::PQ_UPGRADER_IPV4);
    let _result =
        telio_pq::fuzz::parse_get_response(data, 49152, 2, telio_pq::fuzz::PQ_UPGRADER_IPV4);
});
