#!/usr/bin/env bash

set -euxo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIBTELIO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
RESULTS_DIR="${LIBTELIO_ROOT}/benchmark_results"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}  Libtelio Comprehensive Benchmarks${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""

mkdir -p "${RESULTS_DIR}"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
RESULTS_SUBDIR="${RESULTS_DIR}/${TIMESTAMP}"
mkdir -p "${RESULTS_SUBDIR}"

echo -e "${GREEN}Results will be saved to: ${RESULTS_SUBDIR}${NC}"
echo ""

run_rust_benchmarks() {
    echo -e "${YELLOW}========================================${NC}"
    echo -e "${YELLOW}  Running Rust Microbenchmarks${NC}"
    echo -e "${YELLOW}========================================${NC}"
    echo ""
    
    cd "${LIBTELIO_ROOT}"
    
    echo -e "${BLUE}[1/4] Running telio-crypto benchmarks...${NC}"
    cargo bench --package telio-crypto --bench crypto_bench 2>&1 | tee "${RESULTS_SUBDIR}/crypto_bench.log"
    
    echo -e "${BLUE}[2/4] Running telio-relay benchmarks...${NC}"
    cargo bench --package telio-relay --bench relay_bench 2>&1 | tee "${RESULTS_SUBDIR}/relay_bench.log"
    
    echo -e "${BLUE}[3/4] Running telio-proto benchmarks...${NC}"
    cargo bench --package telio-proto --bench proto_bench 2>&1 | tee "${RESULTS_SUBDIR}/proto_bench.log"
    
    echo -e "${BLUE}[4/4] Running libtelio device benchmarks...${NC}"
    cargo bench --package telio --bench device_bench 2>&1 | tee "${RESULTS_SUBDIR}/device_bench.log"
    
    echo ""
    echo -e "${GREEN}✓ Rust microbenchmarks completed${NC}"
    echo ""
}

run_natlab_tests() {
    echo -e "${YELLOW}========================================${NC}"
    echo -e "${YELLOW}  Running Natlab Performance Tests${NC}"
    echo -e "${YELLOW}========================================${NC}"
    echo ""
    
    cd "${LIBTELIO_ROOT}/nat-lab"
    
    if [ ! -f "uv.lock" ]; then
        echo -e "${RED}Error: Natlab environment not set up.${NC}"
        echo -e "${YELLOW}Please run 'uv sync' in nat-lab directory first.${NC}"
        echo -e "${YELLOW}See nat-lab/README.md for setup instructions.${NC}"
        return 1
    fi
    
    if [ ! -f "run_local.py" ]; then
        echo -e "${RED}Error: run_local.py not found in nat-lab directory.${NC}"
        return 1
    fi
    
    echo -e "${BLUE}Building libtelio and running performance tests...${NC}"
    echo -e "${YELLOW}Note: This will build libtelio if not already built.${NC}"
    echo ""
    
    if python3 run_local.py --perf-tests -v 2>&1 | tee "${RESULTS_SUBDIR}/natlab_performance.log"; then
        echo ""
        echo -e "${GREEN}✓ Natlab performance tests completed${NC}"
        
        # Copy performance results if they exist
        if [ -d "logs" ]; then
            echo -e "${BLUE}Copying performance results...${NC}"
            find logs -name "*performance*.json" -exec cp {} "${RESULTS_SUBDIR}/" \; 2>/dev/null || true
        fi
    else
        echo ""
        echo -e "${RED}✗ Natlab performance tests failed${NC}"
        echo -e "${YELLOW}Check ${RESULTS_SUBDIR}/natlab_performance.log for details${NC}"
        return 1
    fi
    
    echo ""
}

generate_summary() {
    echo -e "${YELLOW}========================================${NC}"
    echo -e "${YELLOW}  Generating Summary Report${NC}"
    echo -e "${YELLOW}========================================${NC}"
    echo ""
    
    SUMMARY_FILE="${RESULTS_SUBDIR}/SUMMARY.md"
    
    cat > "${SUMMARY_FILE}" << EOF
# LibTelio Benchmark Results

**Date:** $(date)
**Results Directory:** ${RESULTS_SUBDIR}

## Rust Microbenchmarks

### Crypto Benchmarks
- Location: \`libtelio/crates/telio-crypto/benches/crypto_bench.rs\`
- Results: \`crypto_bench.log\`
- Criterion HTML: \`target/criterion/\`

### Relay Benchmarks
- Location: \`libtelio/crates/telio-relay/benches/relay_bench.rs\`
- Results: \`relay_bench.log\`
- Criterion HTML: \`target/criterion/\`

### Protocol Benchmarks
- Location: \`libtelio/crates/telio-proto/benches/proto_bench.rs\`
- Results: \`proto_bench.log\`
- Criterion HTML: \`target/criterion/\`

### Device Benchmarks
- Location: \`libtelio/benches/device_bench.rs\`
- Results: \`device_bench.log\`
- Criterion HTML: \`target/criterion/\`

## Natlab Performance Tests

### VPN Connection Performance
- Location: \`libtelio/nat-lab/performance_tests/test_vpn_connection_performance.py\`
- Results: \`natlab_vpn_performance.log\`
- JSON Results: \`performance_results.json\` (if available)

## Viewing Results

### Criterion HTML Reports
Criterion generates detailed HTML reports with graphs and statistics:
\`\`\`bash
# Open in browser
firefox ${LIBTELIO_ROOT}/target/criterion/report/index.html
\`\`\`

### Raw Logs
All raw benchmark logs are saved in this directory.

## Next Steps

1. **Analyze Results**: Review the logs and HTML reports to identify bottlenecks
2. **Compare Baselines**: Use criterion's baseline comparison feature
3. **Optimize**: Implement optimizations based on findings
4. **Re-benchmark**: Run this script again to measure improvements

## Optimization Tools

### eBPF Monitoring (Production)
- Location: \`libtelio/clis/nordvpnlite/nordvpnlite-ebpf/\`
- Build: \`cd libtelio/clis/nordvpnlite && ./scripts/build_ebpf.sh\`
- Run: \`sudo ./target/release/nordvpnlite-ebpf-user\`

### Performance Monitor
- Location: \`libtelio/clis/nordvpnlite/src/bin/perf_monitor.rs\`
- Build: \`cargo build --release --bin perf_monitor\`
- Run: \`./target/release/perf_monitor\`
EOF
    
    echo -e "${GREEN}✓ Summary report generated: ${SUMMARY_FILE}${NC}"
    echo ""
}

main() {
    RUN_RUST=true
    RUN_NATLAB=true
    
    while [[ $# -gt 0 ]]; do
        case $1 in
            --rust-only)
                RUN_NATLAB=false
                shift
                ;;
            --natlab-only)
                RUN_RUST=false
                shift
                ;;
            --help|-h)
                echo "Usage: $0 [OPTIONS]"
                echo ""
                echo "Options:"
                echo "  --rust-only    Run only Rust microbenchmarks"
                echo "  --natlab-only  Run only natlab performance tests"
                echo "  --help, -h     Show this help message"
                echo ""
                exit 0
                ;;
            *)
                echo -e "${RED}Unknown option: $1${NC}"
                echo "Use --help for usage information"
                exit 1
                ;;
        esac
    done
    
    if [ "$RUN_RUST" = true ]; then
        run_rust_benchmarks
    fi
    
    if [ "$RUN_NATLAB" = true ]; then
        run_natlab_tests
    fi
    
    # Generate summary
    generate_summary
    
    echo -e "${GREEN}========================================${NC}"
    echo -e "${GREEN}  All Benchmarks Completed!${NC}"
    echo -e "${GREEN}========================================${NC}"
    echo ""
    echo -e "Results saved to: ${BLUE}${RESULTS_SUBDIR}${NC}"
    echo -e "Summary report: ${BLUE}${SUMMARY_FILE}${NC}"
    echo ""
    echo -e "View Criterion HTML reports:"
    echo -e "  ${BLUE}firefox ${LIBTELIO_ROOT}/target/criterion/report/index.html${NC}"
    echo ""
}

# Run main function
main "$@"
