use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use std::hint::black_box;
use telio_crypto::encryption::{
    decrypt_request, decrypt_response, encrypt_request, encrypt_response,
};
use telio_crypto::SecretKey;

// Benchmark configuration
const PACKET_SIZES: &[usize] = &[64, 512, 1024, 1500, 4096, 9000];

/// Benchmark WireGuard key generation
fn bench_key_generation(c: &mut Criterion) {
    c.bench_function("key_generation", |b| {
        b.iter(|| {
            let secret = SecretKey::gen();
            let public = secret.public();
            black_box((secret, public))
        });
    });
}

/// Benchmark ECDH key exchange
fn bench_ecdh(c: &mut Criterion) {
    c.bench_function("ecdh_key_exchange", |b| {
        b.iter(|| {
            let secret1 = SecretKey::gen();
            let secret2 = SecretKey::gen();
            let public2 = secret2.public();

            // Perform ECDH
            let shared = secret1.ecdh(&public2);
            black_box(shared)
        });
    });
}

/// Benchmark request encryption/decryption
fn bench_request_crypto(c: &mut Criterion) {
    let mut group = c.benchmark_group("request_crypto");

    for size in PACKET_SIZES {
        group.throughput(Throughput::Bytes(*size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), size, |b, &size| {
            let data = vec![0u8; size];
            let secret1 = SecretKey::gen();
            let secret2 = SecretKey::gen();
            let public1 = secret1.public();
            let public2 = secret2.public();

            b.iter(|| {
                // Benchmark request encryption/decryption
                let encrypted =
                    encrypt_request(&data, &mut rand::thread_rng(), &secret1, &public2).unwrap();
                let (decrypted, _) =
                    decrypt_request(&encrypted, &secret2, |pk| pk == &public1).unwrap();
                black_box(decrypted)
            });
        });
    }
    group.finish();
}

/// Benchmark response encryption/decryption
fn bench_response_crypto(c: &mut Criterion) {
    let mut group = c.benchmark_group("response_crypto");

    for size in PACKET_SIZES {
        group.throughput(Throughput::Bytes(*size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), size, |b, &size| {
            let data = vec![0u8; size];
            let secret1 = SecretKey::gen();
            let secret2 = SecretKey::gen();
            let public1 = secret1.public();
            let public2 = secret2.public();

            b.iter(|| {
                // Benchmark response encryption/decryption
                let encrypted =
                    encrypt_response(&data, &mut rand::thread_rng(), &secret1, &public2).unwrap();
                let decrypted = decrypt_response(&encrypted, &secret2, &public1).unwrap();
                black_box(decrypted)
            });
        });
    }
    group.finish();
}

/// Benchmark encryption only
fn bench_encrypt_only(c: &mut Criterion) {
    let mut group = c.benchmark_group("encrypt_only");

    for size in PACKET_SIZES {
        group.throughput(Throughput::Bytes(*size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), size, |b, &size| {
            let data = vec![0u8; size];
            let secret1 = SecretKey::gen();
            let secret2 = SecretKey::gen();
            let public2 = secret2.public();

            b.iter(|| {
                let encrypted =
                    encrypt_request(&data, &mut rand::thread_rng(), &secret1, &public2).unwrap();
                black_box(encrypted)
            });
        });
    }
    group.finish();
}

/// Benchmark decryption only
fn bench_decrypt_only(c: &mut Criterion) {
    let mut group = c.benchmark_group("decrypt_only");

    for size in PACKET_SIZES {
        group.throughput(Throughput::Bytes(*size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), size, |b, &size| {
            let data = vec![0u8; size];
            let secret1 = SecretKey::gen();
            let secret2 = SecretKey::gen();
            let public1 = secret1.public();
            let public2 = secret2.public();

            // Pre-encrypt the data
            let encrypted =
                encrypt_request(&data, &mut rand::thread_rng(), &secret1, &public2).unwrap();

            b.iter(|| {
                let (decrypted, _) =
                    decrypt_request(&encrypted, &secret2, |pk| pk == &public1).unwrap();
                black_box(decrypted)
            });
        });
    }
    group.finish();
}

criterion_group!(
    benches,
    bench_key_generation,
    bench_ecdh,
    bench_request_crypto,
    bench_response_crypto,
    bench_encrypt_only,
    bench_decrypt_only
);
criterion_main!(benches);
