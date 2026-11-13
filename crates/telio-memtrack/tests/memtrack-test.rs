//! End-to-end check with `TrackingAllocator` installed as the global allocator
//!
//! Runs without the libtest harness (`harness = false`): the runner's own
//! threads and output capturing allocate concurrently and would make exact
//! deltas flaky. Nothing is printed between a baseline and its assertion

use std::hint::black_box;
use std::thread;

use telio_memtrack::TrackingAllocator;

#[global_allocator]
static ALLOC: TrackingAllocator = TrackingAllocator::new();

fn usage() -> u64 {
    ALLOC.allocated()
}

fn vec_with_capacity() {
    let base = usage();
    let v: Vec<u8> = black_box(Vec::with_capacity(1000));
    assert_eq!(usage() - base, 1000);
    drop(v);
    assert_eq!(usage(), base);
}

fn zeroed_vec() {
    let base = usage();
    let v = black_box(vec![0u8; 4096]);
    assert_eq!(usage() - base, 4096);
    drop(v);
    assert_eq!(usage(), base);
}

fn realloc_grow_and_shrink() {
    let base = usage();
    let mut v: Vec<u8> = Vec::with_capacity(16);
    v.extend_from_slice(&[1; 16]);
    v.reserve_exact(10_000);
    assert_eq!(usage() - base, v.capacity() as u64);
    v.shrink_to_fit();
    assert_eq!(v.capacity(), 16);
    assert_eq!(usage() - base, 16);
    drop(black_box(v));
    assert_eq!(usage(), base);
}

fn threads() {
    // Absorb one-time lazily initialized state of the threading runtime
    thread::spawn(|| ()).join().unwrap();

    let base = usage();
    let handles: Vec<_> = (0..8)
        .map(|i| {
            thread::spawn(move || {
                let mut kept = Vec::new();
                for j in 0..1000 {
                    kept.push(black_box(vec![0u8; 1 + (i * j) % 257]));
                    if j % 3 == 0 {
                        kept.pop();
                    }
                }
                // Hand the allocations back to be freed on another thread
                kept
            })
        })
        .collect();
    let results: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
    assert!(usage() > base);
    drop(results);
    assert_eq!(usage(), base);
}

fn main() {
    let tests: [(&str, fn()); 4] = [
        ("vec_with_capacity", vec_with_capacity),
        ("zeroed_vec", zeroed_vec),
        ("realloc_grow_and_shrink", realloc_grow_and_shrink),
        ("threads", threads),
    ];
    for (name, test) in tests {
        test();
        println!("test {name} ... ok");
    }
}
