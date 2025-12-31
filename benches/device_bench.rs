use std::hint::black_box;
use std::time::{Duration, Instant};

use criterion::{criterion_group, criterion_main, Criterion};

use telio::device::Device;
use telio_model::features::{FeatureLana, Features};

const SAMPLE_SIZE: usize = 50;
const CLEANUP_DELAY_MS: u64 = 10;

fn bench_device_new(c: &mut Criterion) {
    let mut group = c.benchmark_group("device_lifecycle");

    group.sample_size(SAMPLE_SIZE);

    group.bench_function("new", |b| {
        b.iter_custom(|iters| {
            let mut total = Duration::ZERO;
            for _ in 0..iters {
                let start = Instant::now();
                let mut device = black_box(Device::new(Features::default(), |_| {}, None).unwrap());
                total += start.elapsed();

                // Cleanup: shutdown async runtime to free resources
                device.shutdown_art();
                // Small delay to allow OS to reclaim resources
                std::thread::sleep(Duration::from_millis(CLEANUP_DELAY_MS));
            }
            total
        });
    });

    group.finish();
}

fn bench_device_shutdown(c: &mut Criterion) {
    let mut group = c.benchmark_group("device_lifecycle");

    group.sample_size(SAMPLE_SIZE);

    group.bench_function("shutdown", |b| {
        b.iter_custom(|iters| {
            let mut total = Duration::ZERO;
            for _ in 0..iters {
                // Setup: create device outside measurement
                let mut device = Device::new(Features::default(), |_| {}, None).unwrap();

                // Measure shutdown time
                let start = Instant::now();
                device.shutdown_art();
                total += start.elapsed();

                // Small delay to allow OS to reclaim resources
                std::thread::sleep(Duration::from_millis(CLEANUP_DELAY_MS));
            }
            total
        });
    });

    group.finish();
}

fn bench_device_new_with_lana(c: &mut Criterion) {
    let mut group = c.benchmark_group("device_lifecycle");

    group.sample_size(SAMPLE_SIZE);

    group.bench_function("new_with_lana", |b| {
        b.iter_custom(|iters| {
            let mut total = Duration::ZERO;
            let features = Features {
                lana: Some(FeatureLana::default()),
                ..Default::default()
            };
            for _ in 0..iters {
                let start = Instant::now();
                let mut device = black_box(Device::new(features.clone(), |_| {}, None).unwrap());
                total += start.elapsed();

                device.shutdown_art();
                std::thread::sleep(Duration::from_millis(CLEANUP_DELAY_MS));
            }
            total
        });
    });

    group.finish();
}

fn bench_device_shutdown_with_lana(c: &mut Criterion) {
    let mut group = c.benchmark_group("device_lifecycle");

    group.sample_size(SAMPLE_SIZE);

    group.bench_function("shutdown_with_lana", |b| {
        b.iter_custom(|iters| {
            let mut total = Duration::ZERO;
            let features = Features {
                lana: Some(FeatureLana::default()),
                ..Default::default()
            };
            for _ in 0..iters {
                let mut device = Device::new(features.clone(), |_| {}, None).unwrap();

                let start = Instant::now();
                device.shutdown_art();
                total += start.elapsed();

                std::thread::sleep(Duration::from_millis(CLEANUP_DELAY_MS));
            }
            total
        });
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_device_new,
    bench_device_shutdown,
    bench_device_new_with_lana,
    bench_device_shutdown_with_lana,
);
criterion_main!(benches);
