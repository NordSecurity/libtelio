# Nat-Lab

Nat-Lab provides a reproducible, containerized environment for testing libtelio end-to-end across different networking scenarios (NATs, DERP, UPNP, etc.), plus a runner to build libtelio and execute the pytest-based suite locally.

- Orchestration scripts: [natlab.py](natlab.py) (environment lifecycle), [run_local.py](run_local.py) (build and test runner)
- Tests: [tests/](tests)
- Topology: [docker-compose.yml](docker-compose.yml), doc: [network.md](network.md)
- Coding standards and tools: [pyproject.toml](pyproject.toml), authoring guidance: [guidelines.md](guidelines.md)

Note: CI is the canonical execution environment. Local runs are supported where possible and are helpful for day-to-day development.

## Contents

- Quickstart
- Requirements
- Environment lifecycle (start/stop/restart/check)
- Running tests locally
- Selecting tests with markers
- Formatting, linting, and type checking
- Dependency management
- Network topology diagram
- Architecture
- Troubleshooting
- Repository layout tips

## Quickstart

1. Install prerequisites

- Docker (Compose v2). If Docker Server < 28.0, Nat-Lab auto-fallback to a compatible bridge mode (see Troubleshooting).
- Python as per [.python-version](.python-version). Current pin: cpython-3.11 (3.10+ may work; 3.11 is recommended).
- uv (<https://docs.astral.sh/uv/>)
- just (<https://just.systems/>)

1. Sync Python dependencies
From [nat-lab dir](libtelio/nat-lab):

```bash
uv sync
```

1. Start the Nat-Lab infrastructure
From [nat-lab dir](libtelio/nat-lab):

```bash
python3 natlab.py start
# or via uv to isolate env:
uv run python3 natlab.py start
```

This builds and brings up the Docker-compose environment and generates gRPC stubs for ENS. See [python.start()](natlab.py) and [python.generate_grpc()](natlab.py).

1. Build libtelio and run tests
From [nat-lab dir](libtelio/nat-lab):

```bash
uv run python3 run_local.py
```

This will:

- Optionally verify setup correctness (see [python.verify_setup_correctness()](run_local.py))
- Build the required libtelio binaries (see [python.run_build_command()](run_local.py))
- Run type checks (mypy)
- Run pytest with default selection and timeouts (see [python.main()](run_local.py) and [python.get_pytest_arguments()](run_local.py))

## Requirements

- OS: Linux host recommended for full container suite; macOS partially supported (see options below). Windows testing leverages a Windows VM.
- Docker: Docker Engine with Compose v2. See Troubleshooting for version-specific behavior.
- Resources: Builds can be memory heavy. At least 16 GB RAM recommended (see warning in [python.main()](run_local.py)).
- Python: 3.10+ with [uv](https://docs.astral.sh/uv/) for dependency management.

## Environment lifecycle

The environment lifecycle is managed by [natlab.py](natlab.py).

- Start

```bash
uv run python3 natlab.py start
```

- Stop

```bash
uv run python3 natlab.py stop
```

- Kill (SIGKILL containers) and Stop

```bash
uv run python3 natlab.py kill
```

- Restart (kill then start)

```bash
uv run python3 natlab.py restart
```

- Recreate running containers (recreate only currently running services)

```bash
uv run python3 natlab.py recreate
```

- Check that all containers are running

```bash
uv run python3 natlab.py check-containers
```

### Start modifiers (skip heavy services)

- Lightweight bring-up (skips Windows, macOS, fullcone, NLX):

```bash
uv run python3 natlab.py start --lite-mode
```

- Skip specific groups:

```bash
uv run python3 natlab.py start --skip-windows --skip-mac --skip-nlx --skip-fullcone
```

- Skip an individual Windows VM:

```bash
uv run python3 natlab.py start --skip-windows-1
uv run python3 natlab.py start --skip-windows-2
```

If a service is missing, the script prints compose logs for that service and fails. See [python.check_containers()](natlab.py).

## Running tests locally

Use [run_local.py](run_local.py) to build and run the test-suite. Common flags:

- -o OS                Host OS for building binaries [linux|darwin]; default: linux
- --restart            Restart build container before building
- -k "expr"            Pytest -k expression
- -m "markexpr"        Pytest mark expression
- -x                   Stop on first failure
- -v                   Show live stdout from tests
- --reruns N           Rerun failures N times
- --count N            Repeat tests N times
- --windows            Include “windows” mark
- --mac                Include “mac” mark
- --linux-native       Include “linux_native” mark
- --utils              Include “utils” mark
- --moose              Build with moose features
- --nobuild            Skip building libtelio
- --notests            Skip running tests
- --notypecheck        Skip mypy
- --telio-debug        Use debug binaries (sets TELIO_BIN_PROFILE=debug)
- --no-verify-setup-correctness  Disable verification of setup correctness

### Examples

- Run default selection (excludes nat, windows, mac, linux_native, long, moose):

```bash
uv run python3 run_local.py
```

- Run a single test by name:

```bash
uv run python3 run_local.py -k test_direct_connection
```

- Run Windows-marked tests (requires Windows VM available to runners):

```bash
uv run python3 run_local.py --windows
```

- Run with debug libtelio and verbose output:

```bash
uv run python3 run_local.py --telio-debug -v
```

## Selecting tests with markers

Markers are defined in [pyproject.toml](pyproject.toml). Useful ones:

- nat           test only passes once before env restart
- windows       requires Windows VM
- mac           requires macOS VM
- linux_native  tests using native WireGuard on Linux
- long          long-running tests
- moose         requires build with “moose”
- ipv4 / ipv6 / ipv4v6
- utils

### To include a marker

```bash
uv run python3 run_local.py -m "utils"
```

By default, [python.get_pytest_arguments()](run_local.py) excludes nat, windows, mac, linux_native, long, moose unless you opt-in via flags.

## Formatting, linting, and type checking

- Using just:

```bash
just black && just isort && just autoflake
just mypy && just pylint
```

- Without just (equivalents):

```bash
uv run black .
uv run isort .
uv run autoflake -r -i .
uv run mypy .
uv run pylint .
```

Configuration lives in [pyproject.toml](pyproject.toml) for black, isort, autoflake, mypy, pylint, and pytest.

## Dependency management

All dependencies are locked. See [pyproject.toml](pyproject.toml).

- Install/Sync:

```bash
uv sync
```

- Lock (refresh lockfile):

```bash
uv lock
```

- Upgrade a dependency:
  - Edit [pyproject.toml](pyproject.toml)
  - Then:

```bash
uv sync
```

See uv docs for advanced flows.

## Network topology diagram

See [network.md](network.md) for an up-to-date topology description, generated from [docker-compose.yml](docker-compose.yml).
Regenerate the diagram after changes:

```bash
python3 utils/generate_network_diagram.py docker-compose.yml network.md
```

## Architecture

When a natlab test is run, the actual test is run on the machine/VM/container that is acting as the test host, but it needs to interact with instances of libtelio on other containers/VMs. Otherwise, we wouldn't be able to enable VPN, check events, etc which are essential to having tests we can trust. In the past, we would start `tcli` on the relevant container/VM and then interact with it over stdout/stdin. Since libtelio v5 we are generating our FFI bindings with UniFFI, and with that we decided that it would be good to use the generated bindings in natlab as well to dogfood not just the libtelio functionality, but also the bindings themselves. Since natlab is written in python the natural choice was to have UniFFI generate python bindings and use those in natlab, but that meant that we need to change how we interact with the remote libtelio instances. We chose Pyro5 for those interactions.

In a nutshell, Pyro5 is a remote object library for python that allows two different python scripts that may or may not be running on different machines to interact as if they were part of the same script. Pyro5 connections have a `proxy` and a `remote`, where the `remote` has some functionality that the `proxy` needs to interact with. `proxy` and `remote` are disctinct roles in a connection and as such, for a single connection only one side can be `proxy` and only one side can be `remote`. That said, it is entirely possible to have multiple connections between two scripts, allowing either side of the connection to act as both `proxy` and `remote` at the same time. In natlab we are not using that kind of bidirectional connection so for us the separation of concern is clear: the test host is the `proxy` and the container/VM in which libtelio is running is the `remote`.

On the container/VM where libtelio is to be run, we execute `libtelio_remote.py` which dynamically loads the libtelio library (`libtelio.so` on linux, `libtelio.dylib` on macos and `telio.dll` on windows). It then starts a Pyro5 server, letting Pyro5 select an available port. That port is then written to stdout. The `remote` is started by a natlab test `Client` (from `telio.py`), which can pick up the port number by reading the port number from stdout, and creating a `LibtelioProxy` object (from `libtelio_proxy.py`) and pointing it at the IP of the relevant container/VM and the port it just picked up. This kind of port/service discovery is done to avoid port collisions, which was fairly common before when the ports were decided by the test host.

```mermaid
flowchart LR
    subgraph "Host process"
        proxy1[Proxy]
        proxy2[Proxy]
    end
    subgraph "Cone client 1"
        remote1["Remote(192.168.101.104:x)"]
    end
    subgraph "Windows VM 1"
        remote2["Remote(10.55.0.12:y)"]
    end
    proxy1 -->|"Call function"| remote1
    remote1 -->|"Return response"| proxy1
    proxy2 -->|"Call function"| remote2
    remote2 -->|"Return response"| proxy2
```

Pyro5 can't send arbitrary objects back and forth, only objects explicitly exposed over the Pyro5 layer. To still allow sending strongly typed classes between `proxy` and `remote`, there is a serialization implementation that will transparently convert to and from python dictionaries. In `serialization.py` there is a function `init_serialization` that will configure Pyro5 in the current python interpreter to be able to serialize and deserialize pretty much any object. Serializing is one by creating a dict that contains the class name and the data the object holds as a dict, and deserialization is the same but opposite. This way, we can send any objects back and forth without ever having to deal with serialization issues.

Libtelio emits boths logs and events during runtime that are potentially relevant for our natlab tests, so we need to be able to pick them up. On the `remote` where the libtelio instance is actually being run, it's as simple as implementing the `TelioLoggerCb` and `TelioEventCb` and using those to get the events out of libtelio. The logs that are picked up through the callback are directly written to file whereas the events are stored in a list. Each `Client` object (from `telio.py`, which keeps a `proxy` object) then continuously polls for events. The `proxy` can only fetch one event at a time, but when the polling is happening, the `proxy` will get all available events one by one, then wait one second, and then poll again. This way, we get all available events without having to wait more, but we're not burning resources by constantly polling. The 1s timeout could be reduced if necessary.

## Troubleshooting

- Docker version < 28.0 and nat-unprotected
  - Nat-Lab prefers the “nat-unprotected” bridge mode. On Docker Server < 28.0, Nat-Lab will warn and patch compose to use “nat” instead, creating a backup compose file. See [python.check_docker_version_compatibility()](natlab.py).
- Containers failed to start
  - Use:

```bash
uv run python3 natlab.py check-containers
docker compose ps
docker compose logs <service>
```

- The starter already prints logs of missing services; see [python.check_containers()](natlab.py).
- Build killed (SIGKILL) / out of memory
  - Need >= 16 GB RAM or set:

```bash
export NATLAB_REDUCE_PARALLEL_LINKERS=1
```

- See warnings in [python.main()](run_local.py).
- Mismatch between project root HEAD and “triggered-ref”
  - You will see a warning if your local checkout differs from the expected tag/commit used by CI; see [python.verify_setup_correctness()](run_local.py). It’s safe to proceed for local iteration, but results might diverge from CI behavior.

## Repository layout tips

- Entrypoints
  - [natlab.py](natlab.py): lifecycle for Docker environment (start/stop/restart/check), gRPC generation via [python.generate_grpc()](natlab.py)
  - [run_local.py](run_local.py): local build and test driver
- Tests
  - [tests/](tests): pytest suite and utilities under [tests/utils/](tests/utils)
- Guidelines for writing tests
  - See [guidelines.md](guidelines.md) for best practices (parametrize, explicit assertions, event-based waits, cleanup discipline, use wrappers for external tools, etc.)

## CI notes

Nat-Lab runs in CI by default, with its own provisioning. Local runs are for iteration and debugging; ensure parity with CI by keeping your checkout aligned and regenerating artifacts as needed.

## Logs and artifacts (enabling and locations)

### Enable full log capture

- Export before running tests:

```bash
export NATLAB_SAVE_LOGS=1
```

- This starts session-long tcpdump on core nodes at session start/end via [python.pytest_sessionstart()](tests/conftest.py) and [python.pytest_sessionfinish()](tests/conftest.py), which calls [python.start_tcpdump_processes()](tests/conftest.py) and aggregates artifacts.

### Per-test logs and pcaps

- Log directory per test is computed by [python.get_current_test_log_path()](tests/utils/testing.py), resulting in logs/&lt;test_name&gt;[_&lt;params&gt;]
- Python logger writes debug logs when NATLAB_SAVE_LOGS is set via [python.setup_logger()](tests/conftest.py)
  - File: logs/&lt;test_name&gt;[_&lt;params&gt;]/debug.log
- Per-connection pcaps are downloaded at the end of tcpdump contexts (per test) by [python.make_tcpdump()](tests/utils/tcpdump.py)
  - Files: logs/&lt;test_name&gt;[_&lt;params&gt;]/&lt;ConnectionTag&gt;.pcap
  - Name uniqueness handled by [python.find_unique_path_for_tcpdump()](tests/utils/tcpdump.py)
- Session local capture (host):
  - File: logs/local.pcap (created by [python.make_local_tcpdump()](tests/utils/tcpdump.py))

### Kernel and system logs (host and VMs)

- Before tests (if NATLAB_SAVE_LOGS is set) and after tests, [python.collect_kernel_logs()](tests/conftest.py) collects:
  - Host dmesg: logs/dmesg-before_tests.txt and logs/dmesg-after_tests.txt (from [python.save_dmesg_from_host()](tests/conftest.py))
  - Host audit: logs/audit_before_tests.log and logs/audit_after_tests.log (from [python.save_audit_log_from_host()](tests/conftest.py))
- Mac diagnostic reports (in CI or when NATLAB_COLLECT_MAC_DIAGNOSTIC_LOGS=1):
  - Directories: logs/system_diagnostic_reports and logs/user_diagnostic_reports (via [python.collect_mac_diagnostic_reports()](tests/conftest.py))

### Service logs

- DERP relays: logs/derp_01_relay.log, logs/derp_02_relay.log, logs/derp_03_relay.log via [python.collect_nordderper_logs()](tests/conftest.py)
- DNS servers: logs/dns_server_1.log, logs/dns_server_2.log via [python.collect_dns_server_logs()](tests/conftest.py)
- FakeFM (NLX): logs/fakefm.log via [python.save_fakefm_logs()](tests/conftest.py)

### Tcpdump internals (useful when customizing)

- Binary and host file paths are defined in [python.build_tcpdump_command()](tests/utils/tcpdump.py) and PCAP_FILE_PATH map at [python.PCAP_FILE_PATH](tests/utils/tcpdump.py)
- Windows tcpdump in-tests is temporarily disabled (see TODO in [python.make_tcpdump()](tests/utils/tcpdump.py))

### Example: run a single test and keep all logs

```bash
export NATLAB_SAVE_LOGS=1
uv run python3 run_local.py -k test_direct_connection -v
```

  Output artifacts under logs/test_direct_connection*/ with debug.log, per-node pcaps, host local.pcap, and service/system logs.

## SSH access to VMs (dockur_* based)

- Credentials come from composition and SshConnection defaults:
  - Windows VMs: user bill / password gates (see [python.SshConnection.new_connection()](tests/utils/connection/ssh_connection.py))
    - IPs: 192.168.150.54 (VM_WINDOWS_1), 192.168.152.54 (VM_WINDOWS_2) from [python.LAN_ADDR_MAP](tests/config.py)
    - Example:

```bash
ssh bill@192.168.150.54   # password: gates
```

- macOS VM: user root / password jobs (see [python.SshConnection.new_connection()](tests/utils/connection/ssh_connection.py))
  - IP: 192.168.154.54 from [python.LAN_ADDR_MAP](tests/config.py)
  - Example:

```bash
ssh root@192.168.154.54   # password: jobs
```

- Linux VMs (dockur_linux):
  - NLX VM: root / root at 10.0.100.51 ([python.LAN_ADDR_MAP](tests/config.py))

```bash
ssh root@10.0.100.51      # password: root
```

- Fullcone gateway VMs: root / root at 10.0.254.9 and 10.0.254.6 (see services fullcone-gw-01/02 in [docker-compose.yml](docker-compose.yml))

```bash
ssh root@10.0.254.9       # password: root
ssh root@10.0.254.6       # password: root
```

- Notes:
  - On Linux hosts, Docker bridge subnets are reachable from the host (so you can SSH directly to 192.168.x.x and 10.0.x.x addresses).
  - Credentials for dockur_* images are also reflected in service environment in [docker-compose.yml](docker-compose.yml).

## Additional runtime toggles and setup checks (from conftest.py)

- Setup checks run before tests via [python.pytest_runtestloop()](tests/conftest.py).
- Pre-test cleanup runs via [python.pytest_runtest_setup()](tests/conftest.py).
- VM binary copying is handled during collection via [python._copy_vm_binaries_if_needed()](tests/conftest.py).
- See “Environment variables” for toggles and examples.

## Environment variables (cheat sheet)

- NATLAB_SAVE_LOGS
  - Enables session-long and per-test capture and artifact collection; see [python.pytest_sessionstart()](tests/conftest.py:450), [python.pytest_sessionfinish()](tests/conftest.py:459), [python.start_tcpdump_processes()](tests/conftest.py:540).
- NATLAB_SKIP_SETUP_CHECKS
  - Skips environment readiness checks run before tests; see [python.perform_setup_checks()](tests/conftest.py:283).
  - Usage:

```bash
export NATLAB_SKIP_SETUP_CHECKS=1
```

- ENABLE_NATLAB_PROCESS_CLEANUP
  - Enables privileged process cleanup before each test (disabled locally by default); invokes [bin/cleanup_natlab_processes](bin/cleanup_natlab_processes).
  - Toggle executed via [python.kill_natlab_processes()](tests/conftest.py:303).
- NATLAB_COLLECT_MAC_DIAGNOSTIC_LOGS
  - Collects macOS diagnostic reports locally (outside CI); see [python.collect_mac_diagnostic_reports()](tests/conftest.py:519).
- NATLAB_REDUCE_PARALLEL_LINKERS
  - Lower parallel linkers during builds to reduce memory pressure; mentioned in Troubleshooting.
- TELIO_BIN_PROFILE
  - Controls which libtelio binaries paths are used by tests (release|debug). Automatically set by [python.get_pytest_arguments()](run_local.py:180) based on --telio-debug; may be overridden manually if needed.
- GITLAB_CI
  - CI toggle that modifies behavior in a few places (for example, disabling the [docker-compose.yml](docker-compose.yml) port mapping for cone-client-01 and using quiet pulls). See [python.start()](natlab.py:38) and [python.check_docker_version_compatibility()](natlab.py:170).

## Rebuild and apply changes efficiently

### Base image and scripts

- natlab start always rebuilds the “base” image profile with BuildKit:

```bash
uv run python3 natlab.py start
```

Implementation: [python.start()](natlab.py:38) issues docker compose build for the base profile.

### Recreate vs restart

- Recreate currently running services (retains stopped ones):

```bash
uv run python3 natlab.py recreate
```

Implementation: [python.recreate()](natlab.py:222)

- Recreate all services:

```bash
uv run python3 natlab.py recreate-all
```

Implementation: [python.recreate_all()](natlab.py:234)

- Simple restart of running containers (no rebuild):

```bash
uv run python3 natlab.py restart
```

Implementation: [python.restart()](natlab.py:217)

### Regenerate gRPC stubs

- Performed automatically by start, but can be run directly:

```bash
uv run python3 -m grpc_tools.protoc -I../crates/telio-proto/protos --python_out=./bin/grpc_protobuf/ --grpc_python_out=./bin/grpc_protobuf ../crates/telio-proto/protos/ens.proto
```

Helper: [python.generate_grpc()](natlab.py:203)

### Full cleanup tips (use carefully)

- Bring down environment:

```bash
uv run python3 natlab.py stop
```

- Remove leftover networks/containers if you experimented outside natlab (advanced):

```bash
docker network ls
docker network rm <network>     # only if you know it’s safe
docker container prune          # will remove stopped containers
```

## Known limitations and caveats

- macOS hosts
  - Docker Desktop lacks KVM; VM-backed services cannot run. Use lite-mode or skip flags as noted earlier.
  - Local host packet capture (tcpdump) may require sudo; nat-lab will add sudo automatically when needed in [python.make_local_tcpdump()](tests/utils/tcpdump.py:205).
- IPv6
  - The “internet” network has IPv6 enabled in [docker-compose.yml](docker-compose.yml:934). Ensure Docker daemon has IPv6 enabled if running IPv6 tests; otherwise disable IPv6-related markers.
- Security and networking impact
  - On newer Docker versions natlab prefers a special “nat-unprotected” bridge mode; on older Docker it falls back to “nat”. This adjusts NAT/masquerade behavior and may affect firewalling/routing on your workstation. See [python.check_docker_version_compatibility()](natlab.py:170) and comments in [docker-compose.yml](docker-compose.yml).
- Windows as host
  - Full env (with nested virtualization) is not supported on native Windows hosts. Use a Linux host for full coverage or run the lite-mode.

## Editor/IDE setup (to avoid import warnings)

- Use the uv-managed virtual environment as your interpreter:
  - After:

```bash
uv sync
```

Configure your editor to use:

- libtelio/nat-lab/.venv/bin/python (Linux/macOS)
- Run tools via uv to ensure correct sys.path and dependencies:
  - Examples:

```bash
uv run pytest -k test_direct_connection
uv run mypy .
uv run pylint .
```

- Some generated or vendored modules (e.g., [bin/grpc_protobuf/](bin/grpc_protobuf), 3rd-party utilities) may confuse static analyzers until you run “uv sync” and “uv run python3 natlab.py start” at least once (to generate stubs).

## Python version pin

- Python interpreter is defined by [.python-version](.python-version) and currently pinned to cpython-3.11. Use that version for uv and local runs. Example with pyenv:

```bash
pyenv install -s 3.11.9
pyenv local 3.11.9
uv sync
```

## Pytest HTML report

- Nat-Lab enables pytest-html in [pyproject.toml](pyproject.toml) via addopts. Each run writes a self-contained HTML report to:
  - report.html (in the directory you run pytest from; when using run_local.py from Nat-Lab, the file is: libtelio/nat-lab/report.html)
- Open the report:
  - Linux: xdg-open report.html
  - macOS: open report.html
- Customize the output location or file name:
  - pytest --html=out/report.html --self-contained-html
- Notes:
  - The report includes captured logs, durations, and rerun status (if using --reruns). It’s portable for CI artifacts.
