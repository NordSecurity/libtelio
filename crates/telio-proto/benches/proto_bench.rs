use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use std::hint::black_box;
use telio_proto::{Codec, DataMsg, PacketRelayed};

/// Benchmark protocol message encoding
fn bench_message_encoding(c: &mut Criterion) {
    let mut group = c.benchmark_group("message_encoding");

    // Benchmark different message sizes
    for size in [64, 256, 1024, 4096, 16384].iter() {
        group.bench_with_input(BenchmarkId::from_parameter(size), size, |b, &size| {
            let data = vec![0u8; size];

            b.iter(|| {
                let msg = PacketRelayed::Data(DataMsg::new(&data));
                let encoded = msg.encode().unwrap();
                black_box(encoded)
            });
        });
    }

    group.finish();
}

/// Benchmark protocol message decoding
fn bench_message_decoding(c: &mut Criterion) {
    let mut group = c.benchmark_group("message_decoding");

    // Benchmark different message sizes
    for size in [64, 256, 1024, 4096, 16384].iter() {
        group.bench_with_input(BenchmarkId::from_parameter(size), size, |b, &size| {
            let data = vec![0u8; size];
            let msg = PacketRelayed::Data(DataMsg::new(&data));
            let encoded = msg.encode().unwrap();

            b.iter(|| {
                let decoded = PacketRelayed::decode(&encoded).unwrap();
                black_box(decoded)
            });
        });
    }

    group.finish();
}

/// Benchmark encode/decode round trip
fn bench_encode_decode_roundtrip(c: &mut Criterion) {
    let mut group = c.benchmark_group("encode_decode_roundtrip");

    for size in [64, 256, 1024, 4096].iter() {
        group.bench_with_input(BenchmarkId::from_parameter(size), size, |b, &size| {
            let data = vec![0u8; size];

            b.iter(|| {
                let msg = PacketRelayed::Data(DataMsg::new(&data));
                let encoded = msg.encode().unwrap();
                let decoded = PacketRelayed::decode(&encoded).unwrap();
                black_box(decoded)
            });
        });
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_message_encoding,
    bench_message_decoding,
    bench_encode_decode_roundtrip,
);
criterion_main!(benches);
