use criterion::{criterion_group, criterion_main, BatchSize, BenchmarkId, Criterion};
use std::collections::HashSet;
use std::hint::black_box;
use telio_crypto::SecretKey;
use telio_model::config::Server;
use telio_relay::derp::{Config as DerpConfig, SortedServers};

/// Benchmark DERP config creation
fn bench_derp_config_creation(c: &mut Criterion) {
    c.bench_function("derp_config_creation", |b| {
        b.iter(|| {
            let secret_key = SecretKey::gen();
            let servers = vec![
                Server {
                    hostname: "test1.example.com".to_string(),
                    relay_port: 8765,
                    weight: 1,
                    ..Default::default()
                },
                Server {
                    hostname: "test2.example.com".to_string(),
                    relay_port: 8765,
                    weight: 2,
                    ..Default::default()
                },
            ];

            let config = DerpConfig {
                secret_key,
                servers: SortedServers::new(servers),
                meshnet_peers: HashSet::new(),
                ..Default::default()
            };

            black_box(config)
        });
    });
}

/// Benchmark key generation for DERP
fn bench_key_generation(c: &mut Criterion) {
    let mut group = c.benchmark_group("derp_keys");

    // Benchmark key generation
    group.bench_function("secret_key_gen", |b| {
        b.iter(|| {
            let key = SecretKey::gen();
            black_box(key)
        });
    });

    // Benchmark public key derivation
    group.bench_function("public_key_derive", |b| {
        b.iter_batched(
            || SecretKey::gen(),
            |secret_key| {
                let public_key = secret_key.public();
                black_box(public_key)
            },
            BatchSize::SmallInput,
        );
    });

    group.finish();
}

/// Benchmark server list operations
fn bench_server_operations(c: &mut Criterion) {
    c.bench_function("sorted_servers_creation", |b| {
        b.iter(|| {
            let servers = vec![
                Server {
                    hostname: "relay1.example.com".to_string(),
                    relay_port: 8765,
                    weight: 1,
                    ..Default::default()
                },
                Server {
                    hostname: "relay2.example.com".to_string(),
                    relay_port: 8765,
                    weight: 2,
                    ..Default::default()
                },
                Server {
                    hostname: "relay3.example.com".to_string(),
                    relay_port: 8765,
                    weight: 3,
                    ..Default::default()
                },
            ];

            let sorted = SortedServers::new(servers);
            black_box(sorted)
        });
    });
}

criterion_group!(
    benches,
    bench_derp_config_creation,
    bench_key_generation,
    bench_server_operations,
);
criterion_main!(benches);
