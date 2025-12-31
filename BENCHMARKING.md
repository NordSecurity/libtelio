# Libtelio Benchmarking Guide

This document describes the comprehensive benchmarking infrastructure for libtelio and nordvpnlite.

## Overview

The benchmarking suite is organized following Rust workspace best practices:

1. **Crate-level microbenchmarks** - Located at each crate directory
2. **Library-level benchmarks** - Located at `libtelio/benches/` for cross-crate functionality
3. **Integration performance tests** - Located in `nat-lab/performance_tests/` for real VPN testing
4. **Production monitoring tools** - Located in `nordvpnlite/` for runtime performance analysis

## Quick Start

### Run All Benchmarks

```bash
cd libtelio
./scripts/run_all_benchmarks.sh
```

This will:

- Run all Rust microbenchmarks (crypto, relay, proto, device)
- Run natlab VPN performance tests
- Generate a comprehensive summary report
- Save results with timestamp in `benchmark_results/`

### Run Specific Benchmark Suites

```bash
# Rust microbenchmarks only
./scripts/run_all_benchmarks.sh --rust-only

# Natlab performance tests only
./scripts/run_all_benchmarks.sh --natlab-only
```

## Benchmark Organization

### 1. Crate-Level Microbenchmarks

These benchmarks test individual crate performance in isolation.

#### Crypto Benchmarks (`telio-crypto`)

**Location:** `libtelio/crates/telio-crypto/benches/crypto_bench.rs`

Tests:

- Key generation (SecretKey, PublicKey)
- ECDH key exchange
- Encryption/decryption operations
- Different payload sizes (64B - 16KB)

```bash
cargo bench --package telio-crypto --bench crypto_bench
```

#### Relay Benchmarks (`telio-relay`)

**Location:** `libtelio/crates/telio-relay/benches/relay_bench.rs`

Tests:

- DERP configuration creation
- Message serialization/deserialization
- Multiplexer operations

```bash
cargo bench --package telio-relay --bench relay_bench
```

#### Protocol Benchmarks (`telio-proto`)

**Location:** `libtelio/crates/telio-proto/benches/proto_bench.rs`

Tests:

- Protocol message encoding
- Protocol message decoding
- Encode/decode round trips
- Different message sizes (64B - 16KB)

```bash
cargo bench --package telio-proto --bench proto_bench
```

### 2. Library-Level Benchmarks

These benchmarks test cross-crate functionality and high-level APIs.

#### Device Benchmarks (`telio`)

**Location:** `libtelio/benches/device_bench.rs`

Tests:

- Device creation and initialization
- Device start/stop cycles
- Exit node connection setup

```bash
cargo bench --package telio --bench device_bench
```

### 3. Integration Performance Tests (Natlab)

Real-world VPN performance testing using Docker containers and iperf3.

**Location:** `libtelio/nat-lab/performance_tests/test_vpn_connection_performance.py`

Tests:

- Baseline network performance (no VPN)
- VPN connection performance
- Upload/download throughput
- TCP retransmissions
- RTT statistics (min/max/mean)

Metrics collected:

- Upload speed (Mbits/sec)
- Download speed (Mbits/sec)
- Retransmissions count
- Round-trip time statistics
- CPU usage
- Memory usage

```bash
cd nat-lab
pytest performance_tests/test_vpn_connection_performance.py -v
```

### 4. Production Monitoring Tools

Tools for runtime performance analysis in production environments.

#### Performance Monitor

**Location:** `libtelio/clis/nordvpnlite/src/bin/perf_monitor.rs`

Real-time monitoring of:

- CPU usage
- Memory consumption
- Network throughput
- Connection statistics

```bash
cargo build --release --bin perf_monitor
./target/release/perf_monitor
```

#### eBPF Packet Inspector

**Location:** `libtelio/clis/nordvpnlite/nordvpnlite-ebpf/`

Kernel-level packet inspection using XDP:

- Packet counts
- Packet sizes
- Protocol distribution
- Zero-overhead monitoring

```bash
cd libtelio/clis/nordvpnlite
./scripts/build_ebpf.sh
sudo ./target/release/nordvpnlite-ebpf-user
```

## Viewing Results

### Criterion HTML Reports

Criterion generates detailed HTML reports with graphs and statistical analysis:

```bash
# Open the main report
firefox libtelio/target/criterion/report/index.html

# Or view specific benchmark
firefox libtelio/target/criterion/crypto_bench/report/index.html
```

Reports include:

- Performance graphs over time
- Statistical analysis (mean, median, std dev)
- Regression detection
- Comparison with previous runs

### Benchmark Results Directory

All results are saved with timestamps:

```bash
libtelio/benchmark_results/
└── 20231230_120000/
    ├── SUMMARY.md                    # Overview of all results
    ├── crypto_bench.log              # Crypto benchmark output
    ├── relay_bench.log               # Relay benchmark output
    ├── proto_bench.log               # Protocol benchmark output
    ├── device_bench.log              # Device benchmark output
    ├── natlab_vpn_performance.log    # Natlab test output
    └── performance_results.json      # Natlab metrics (JSON)
```

## Baseline Comparison

Criterion supports baseline comparison to track performance over time:

```bash
# Save current results as baseline
cargo bench --package telio-crypto -- --save-baseline before-optimization

# Make optimizations...

# Compare against baseline
cargo bench --package telio-crypto -- --baseline before-optimization
```

## Performance Optimization Workflow

1. **Run baseline benchmarks**

   ```bash
   ./scripts/run_all_benchmarks.sh
   ```

2. **Analyze results**
   - Review Criterion HTML reports
   - Check natlab performance metrics
   - Identify bottlenecks

3. **Profile with production tools**

   ```bash
   # CPU profiling
   cargo build --release --bin perf_monitor
   ./target/release/perf_monitor
   
   # Packet-level analysis
   cd libtelio/clis/nordvpnlite
   ./scripts/build_ebpf.sh
   sudo ./target/release/nordvpnlite-ebpf-user
   ```

4. **Implement optimizations**
   - Code improvements
   - Algorithm changes
   - eBPF-based optimizations (if applicable)

5. **Re-run benchmarks**

   ```bash
   ./scripts/run_all_benchmarks.sh
   ```

6. **Compare results**
   - Use Criterion baseline comparison
   - Compare natlab JSON metrics
   - Verify improvements

## Adding New Benchmarks

### Adding a Crate-Level Benchmark

1. Create benchmark file:

   ```bash
   mkdir -p crates/your-crate/benches
   touch crates/your-crate/benches/your_bench.rs
   ```

2. Add to `Cargo.toml`:

   ```toml
   [dev-dependencies]
   criterion = "0.5"
   
   [[bench]]
   name = "your_bench"
   harness = false
   ```

3. Write benchmark using Criterion:

   ```rust
   use criterion::{criterion_group, criterion_main, Criterion};
   
   fn bench_function(c: &mut Criterion) {
       c.bench_function("test_name", |b| {
           b.iter(|| {
               // Code to benchmark
           });
       });
   }
   
   criterion_group!(benches, bench_function);
   criterion_main!(benches);
   ```

4. Update `scripts/run_all_benchmarks.sh` to include your benchmark

### Adding a Natlab Performance Test

1. Create test file in `nat-lab/performance_tests/`
2. Use existing helpers from `test_vpn_connection_performance.py`
3. Follow pytest conventions
4. Save metrics to JSON for analysis

## CI/CD Integration

Benchmarks can be integrated into CI/CD pipelines:

```yaml
benchmark:
  stage: test
  script:
    - cd libtelio
    - ./scripts/run_all_benchmarks.sh --rust-only
  artifacts:
    paths:
      - libtelio/benchmark_results/
      - libtelio/target/criterion/
    expire_in: 30 days
```

## Troubleshooting

### Benchmarks fail to compile

```bash
cargo clean
cargo build --release
cargo bench --no-run
```

### Natlab tests don't run

Follow nat-lab/README.md for setup instructions

### eBPF tools require root

eBPF XDP programs require root privileges:

```bash
sudo ./target/release/nordvpnlite-ebpf-user
```

## Best Practices

1. **Run benchmarks on dedicated hardware** - Avoid running on busy systems
2. **Disable CPU frequency scaling** - For consistent results
3. **Run multiple iterations** - Criterion does this automatically
4. **Use baseline comparison** - Track performance over time
5. **Document optimizations** - Note what changed and why
6. **Test real-world scenarios** - Use natlab for integration testing

## References

- [Criterion.rs Documentation](https://bheisler.github.io/criterion.rs/book/)
- [Rust Performance Book](https://nnethercote.github.io/perf-book/)
- [eBPF Documentation](https://ebpf.io/)
- [iperf3 Documentation](https://iperf.fr/)

## Related Documentation

- `nat-lab/README.md` - Natlab setup and usage
- `scripts/run_all_benchmarks.sh` - Automated benchmark runner
