#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Parse a DNS query from the input, then exercise the response encoder
    // (DnsResponseBuilder::build) across every ResponseKind.
    telio_dns::fuzz::fuzz_build_response(data);
});
