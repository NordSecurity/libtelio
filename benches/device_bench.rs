use criterion::{criterion_group, criterion_main, BatchSize, Criterion};
use std::hint::black_box;

use telio::device::{Device, DeviceConfig};
use telio_model::features::Features;
use telio_model::mesh::ExitNode;
use telio_crypto::SecretKey;

/// Benchmark telio device creation and initialization
fn bench_device_creation(c: &mut Criterion) {
    c.bench_function("device_creation", |b| {
        b.iter(|| {
            let features = Features::default();
            let device = Device::new(features, |_| {}, None);
            black_box(device)
        });
    });
}

/// Benchmark telio device start/stop cycle
fn bench_device_start_stop(c: &mut Criterion) {
    c.bench_function("device_start_stop", |b| {
        b.iter_batched(
            || {
                let features = Features::default();
                let device = Device::new(features, |_| {}, None).unwrap();
                let secret_key = SecretKey::gen();
                (device, secret_key)
            },
            |(mut device, secret_key)| {
                let config = DeviceConfig {
                    private_key: secret_key,
                    name: Some("bench_tun".to_string()),
                    ..Default::default()
                };
                
                device.start(config).unwrap();
                device.stop();
                black_box(device)
            },
            BatchSize::SmallInput,
        );
    });
}

/// Benchmark exit node connection
fn bench_exit_node_connection(c: &mut Criterion) {
    c.bench_function("exit_node_connection", |b| {
        b.iter_batched(
            || {
                let features = Features::default();
                let device = Device::new(features, |_| {}, None).unwrap();
                let secret_key = SecretKey::gen();
                let exit_secret = SecretKey::gen();
                (device, secret_key, exit_secret)
            },
            |(mut device, secret_key, exit_secret)| {
                let config = DeviceConfig {
                    private_key: secret_key,
                    name: Some("bench_tun".to_string()),
                    ..Default::default()
                };
                
                device.start(config).unwrap();
                
                // Create exit node
                let exit_node = ExitNode {
                    identifier: "bench_exit".to_string(),
                    public_key: exit_secret.public(),
                    allowed_ips: None,
                    endpoint: Some("127.0.0.1:51820".parse().unwrap()),
                };
                
                let result = device.connect_exit_node(&exit_node);
                device.stop();
                black_box(result)
            },
            BatchSize::SmallInput,
        );
    });
}

criterion_group!(
    benches,
    bench_device_creation,
    bench_device_start_stop,
    bench_exit_node_connection,
);
criterion_main!(benches);
