# Quickstart

1. Start the minimal Nat-Lab infrastructure required for performance test
From [nat-lab dir](libtelio/nat-lab):

```bash
uv run --isolated ./natlab.py start --services-to-start cone-client-01 vpn-01 photo-album stun-01 core-api derp-01 derp-02 derp-03
```

1. Run performance tests

From [nat-lab dir](libtelio/nat-lab):

```bash
uv run --isolated ./run_local.py --nobuild --perf-tests --notypecheck -v -k test_vpn_connection_performance
```
