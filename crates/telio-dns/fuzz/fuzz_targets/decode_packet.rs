#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Exercise the synchronous decode spine of process_packet:
    // IP version dispatch -> IPv4/IPv6 + UDP/TCP parsing -> DNS query parsing.
    telio_dns::fuzz::fuzz_decode_packet(data);
});
