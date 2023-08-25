#![no_main]

use libfuzzer_sys::fuzz_target;
use telio_proto::{Codec, PacketRelayed, PacketControl};

fuzz_target!(|data: &[u8]| {
    // Should not panic
    let packet = PacketRelayed::decode(data);
    if let Ok(packet) = packet {
        let _out = packet.encode().unwrap();
        // Can't compare here since protobuf has multiple valid encodings for a given message.
        // assert_eq!(data, _out);
    }
    let packet = PacketControl::decode(data);
    if let Ok(packet) = packet {
        let _out = packet.encode().unwrap();
        // Can't compare here since protobuf has multiple valid encodings for a given message.
        // assert_eq!(data, _out);
    }
});
