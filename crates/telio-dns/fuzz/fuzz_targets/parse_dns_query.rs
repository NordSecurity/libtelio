#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Chain both parser stages: parse, then on success run the .nord query finder.
    if let Ok(packet) = telio_dns::fuzz::parse_dns_query_packet(data) {
        let _ = telio_dns::fuzz::find_nord_query(&packet);
    }
});
