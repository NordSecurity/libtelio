"""Regression tests for LLT-4961 / LLT-4948 - libtelio must not replay the tokio
interval ticks it missed while a device was asleep in a single burst.

Two suspend mechanisms are exercised. tokio `Interval`/`Instant` run on
CLOCK_MONOTONIC (QPC on Windows, mach_absolute_time on macOS), which - unlike
CLOCK_BOOTTIME - does NOT count time the OS spent suspended (see telio-utils
`instant.rs`, which keeps a separate boot_time clock exactly for that reason).
Either the clock jumps forward on resume (tokio sees overdue ticks, which the
Delay fix must not replay in a burst) or it freezes (no ticks missed, nothing to
burst); both cases must be burst-free:

* `test_no_burst_after_monotonic_jump` - the container/VM is frozen with the
  cgroup freezer while the host keeps running, so CLOCK_MONOTONIC jumps forward
  on resume and tokio sees many overdue ticks. This models process-freeze style
  sleep (mobile background / Android Doze, VM pause / live-migration, CPU
  starvation) and is the condition that actually triggered LLT-4947's burst, so
  it is the real regression test for the Burst -> Delay fix. Runs on Linux,
  Windows and macOS; the clock jump is verified, so it can never pass vacuously.

* `test_no_burst_after_system_suspend` - the VM is genuinely suspended by
  halting its vCPUs through the QEMU monitor (`stop`/`cont`, the same operation
  as `virsh suspend`), then resumed. The clock behaviour is platform dependent
  here - Windows QPC freezes (a genuine suspend-to-RAM, no missed ticks) while
  macOS mach time jumps (missed ticks) - and neither may burst. VM-only (docker
  containers have no hypervisor to suspend). ACPI S3 via the guest agent is not
  usable in the dockur images, so the hypervisor-level suspend is used instead.
"""

import asyncio
import pytest
from tests.helpers import Environment, SetupParameters, ping_between_all_nodes
from tests.utils.bindings import TelioAdapterType
from tests.utils.connection import Connection, ConnectionTag
from tests.utils.connection.docker_connection import (
    backing_container_id,
    paused_container,
)
from tests.utils.connection.ssh_connection import SshConnection
from tests.utils.python import get_python_binary

# Each tick of libtelio's 5s WireGuard-consolidation poll (src/device.rs) emits
# this debug line. Before LLT-4948 the interval used the default tokio
# `MissedTickBehavior::Burst`, so every tick missed while the device slept fired
# immediately on wake, producing a burst of these lines (LLT-4947). With the
# `Delay` fix only the single overdue tick fires and the 5s cadence resumes.
CONSOLIDATION_LOG = "WG consolidation triggered by tick event"

# The poll period is 5s, so a 60s freeze misses ~12 ticks. A regression would
# replay all of them in a burst right after wake.
SLEEP_DURATION_S = 60
# Settle window after wake before counting. Kept below the 5s poll period so
# that, with the fix, at most the single immediate tick lands in the window.
SETTLE_AFTER_WAKE_S = 3
# With the fix we expect ~1 consolidation right after wake; allow a small margin
# for scheduling jitter. A burst would be far above this (~SLEEP/period ≈ 12).
MAX_CONSOLIDATIONS_AFTER_WAKE = 4


async def _read_guest_monotonic(connection: Connection) -> float:
    """Read the guest's monotonic clock (seconds).

    `time.monotonic()` maps to the same per-platform clock tokio's `Instant`
    uses: CLOCK_MONOTONIC on Linux, QueryPerformanceCounter on Windows and
    mach_absolute_time on macOS. All guests ship python3 (the libtelio test
    proxy runs on it), so this works uniformly across docker and VM clients.
    """
    python = get_python_binary(connection)
    process = connection.create_process(
        [python, "-c", "import time;print(time.monotonic())"], quiet=True
    )
    await process.execute()
    return float(process.get_stdout().strip())


# --- VM suspend, driven through the dockur QEMU monitor ----------------------
# A VM client runs its guest OS in QEMU inside the dockur container. The QEMU
# monitor lives inside that container (telnet on localhost) and is reachable with
# `docker exec`: `stop` suspends the VM (halts the vCPUs - the same operation as
# `virsh suspend`) and `cont` resumes it. How the guest clock behaves across the
# pause is platform dependent (Windows QPC freezes; macOS mach time jumps).
# (ACPI S3 via the guest agent is not usable here: the dockur Windows guest
# reports "suspend-to-ram not supported by OS" and the macOS guest agent has no
# guest-suspend-ram command.)
QEMU_MONITOR_PORT = "7100"
# Real wall-clock time to stay suspended; only needs to clearly exceed the 5s
# poll period.
SUSPEND_DURATION_S = 30


async def _container_exec(container: str, script: str) -> str:
    proc = await asyncio.create_subprocess_exec(
        "docker",
        "exec",
        container,
        "sh",
        "-c",
        script,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.STDOUT,
    )
    out, _ = await proc.communicate()
    return out.decode(errors="replace")


async def _qemu_monitor(container: str, command: str) -> str:
    """Send one HMP command to the QEMU monitor."""
    return await _container_exec(
        container,
        f"printf '%s\\n' '{command}' | nc -w2 localhost {QEMU_MONITOR_PORT}",
    )


async def _wait_for_run_state(container: str, wanted: str, attempts: int = 30) -> bool:
    """Poll the QEMU monitor until `info status` reports the wanted run state."""
    for _ in range(attempts):
        if wanted in (await _qemu_monitor(container, "info status")).lower():
            return True
        await asyncio.sleep(1)
    return False


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "alpha_setup_params, beta_setup_params",
    [
        pytest.param(
            SetupParameters(connection_tag=ConnectionTag.DOCKER_CONE_CLIENT_1),
            SetupParameters(connection_tag=ConnectionTag.DOCKER_CONE_CLIENT_2),
        ),
        pytest.param(
            SetupParameters(
                connection_tag=ConnectionTag.VM_WINDOWS_1,
                adapter_type_override=TelioAdapterType.WINDOWS_NATIVE_TUN,
            ),
            SetupParameters(connection_tag=ConnectionTag.DOCKER_CONE_CLIENT_2),
            marks=pytest.mark.windows,
        ),
        pytest.param(
            SetupParameters(
                connection_tag=ConnectionTag.VM_MAC,
                adapter_type_override=TelioAdapterType.NEP_TUN,
            ),
            SetupParameters(connection_tag=ConnectionTag.DOCKER_CONE_CLIENT_2),
            marks=pytest.mark.mac,
        ),
    ],
)
async def test_no_burst_after_monotonic_jump(
    alpha_setup_params: SetupParameters,  # pylint: disable=unused-argument
    beta_setup_params: SetupParameters,  # pylint: disable=unused-argument
    env_mesh: Environment,
) -> None:
    """Regression test for LLT-4961 / LLT-4948.

    Freezes a connected client with the cgroup freezer, wakes it, and asserts
    libtelio does not replay the interval ticks missed while frozen in a single
    burst. Runs on Linux, Windows and macOS clients.

    This models process-freeze style sleep - mobile background / Android Doze, VM
    pause / live-migration, CPU starvation: while the process (a VM's vCPUs) is
    frozen the host keeps advancing CLOCK_MONOTONIC, so on resume the guest sees
    ~SLEEP_DURATION_S/5s overdue ticks. That monotonic jump is exactly the
    condition that triggered LLT-4947's burst. (A genuine VM suspend, where the
    clock may instead freeze, is covered by test_no_burst_after_system_suspend.)
    The test does not need to wait multiple days: even a handful of missed ticks
    distinguishes `Burst` from the `Delay` fix. The jump is verified to actually
    happen (below), so the no-burst check cannot pass vacuously.
    """
    client_alpha = env_mesh.clients[0]
    connection_alpha = client_alpha.get_connection()
    alpha_tag = connection_alpha.tag

    # Make sure the mesh is up and the consolidation loop is running steadily.
    await ping_between_all_nodes(env_mesh)

    mono_before = await _read_guest_monotonic(connection_alpha)
    consolidations_before = (await client_alpha.log.get()).count(CONSOLIDATION_LOG)

    # VM SSH session can't survive the freeze: detach remote stdout (else EPIPE-crash) + rebuild SSH on wake.
    is_ssh = isinstance(connection_alpha, SshConnection)
    if is_ssh:
        await client_alpha.get_proxy().redirect_stdout_to_logfile()

    # Freeze the client: it does no work, but the monotonic clock keeps moving,
    # so on unpause the poll interval has many overdue ticks.
    async with paused_container(alpha_tag):
        await asyncio.sleep(SLEEP_DURATION_S)

    if is_ssh:
        await connection_alpha.reconnect()

    mono_after = await _read_guest_monotonic(connection_alpha)
    slept = mono_after - mono_before

    # Precondition: the freeze must look like a long sleep to the guest's
    # monotonic clock, otherwise the no-burst check below would be vacuous.
    assert slept >= SLEEP_DURATION_S * 0.5, (
        f"guest monotonic clock advanced only {slept:.1f}s during a"
        f" {SLEEP_DURATION_S}s freeze - the sleep was not simulated (the guest"
        " clock did not jump), so the no-burst check would be meaningless."
    )

    # Give libtelio a moment to wake and process the (now overdue) timers.
    await asyncio.sleep(SETTLE_AFTER_WAKE_S)

    consolidations_after = (await client_alpha.log.get()).count(CONSOLIDATION_LOG)
    burst = consolidations_after - consolidations_before
    assert burst <= MAX_CONSOLIDATIONS_AFTER_WAKE, (
        f"Detected a burst of {burst} WG consolidations within"
        f" {SETTLE_AFTER_WAKE_S}s of waking from a {SLEEP_DURATION_S}s sleep"
        f" (expected <= {MAX_CONSOLIDATIONS_AFTER_WAKE}); missed interval ticks"
        " are being replayed in a burst - see LLT-4948."
    )

    # Sanity check: the consolidation loop must keep ticking after wake (i.e. we
    # measured "no burst", not "interval died"). One more tick within ~2 periods.
    await client_alpha.log.wait_for(CONSOLIDATION_LOG, count=consolidations_after + 1)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "alpha_setup_params, beta_setup_params",
    [
        pytest.param(
            SetupParameters(
                connection_tag=ConnectionTag.VM_WINDOWS_1,
                adapter_type_override=TelioAdapterType.WINDOWS_NATIVE_TUN,
            ),
            SetupParameters(connection_tag=ConnectionTag.DOCKER_CONE_CLIENT_2),
            marks=pytest.mark.windows,
        ),
        pytest.param(
            SetupParameters(
                connection_tag=ConnectionTag.VM_MAC,
                adapter_type_override=TelioAdapterType.NEP_TUN,
            ),
            SetupParameters(connection_tag=ConnectionTag.DOCKER_CONE_CLIENT_2),
            marks=pytest.mark.mac,
        ),
    ],
)
async def test_no_burst_after_system_suspend(
    alpha_setup_params: SetupParameters,  # pylint: disable=unused-argument
    beta_setup_params: SetupParameters,  # pylint: disable=unused-argument
    env_mesh: Environment,
) -> None:
    """VM-suspend counterpart of test_no_burst_after_monotonic_jump.

    Genuinely suspends the guest by halting its vCPUs through the QEMU monitor
    (`stop`, the same operation as `virsh suspend`) and resumes it (`cont`),
    then asserts the mesh reconnects and there is no consolidation burst.

    How the suspend looks to tokio's clock is platform dependent and both cases
    must be burst-free: on Windows the guest QPC freezes across the pause (a
    genuine suspend-to-RAM - no ticks are even missed), while on macOS mach time
    jumps (missed ticks, which the Delay fix must not replay). The proof that the
    VM was really suspended is the monitor's paused/running transition, so the
    test does not depend on either clock behaviour.

    VM-only: docker containers have no hypervisor to suspend. (ACPI S3 via the
    guest agent is not usable in the dockur images - Windows reports
    "suspend-to-ram not supported by OS" and the macOS guest agent has no
    guest-suspend-ram command - so the hypervisor-level suspend is used instead.)
    """
    client_alpha = env_mesh.clients[0]
    connection_alpha = client_alpha.get_connection()
    container = backing_container_id(connection_alpha.tag)

    await ping_between_all_nodes(env_mesh)
    consolidations_before = (await client_alpha.log.get()).count(CONSOLIDATION_LOG)

    # VM SSH session can't survive the suspend: detach remote stdout (else EPIPE-crash) + rebuild SSH on resume.
    await client_alpha.get_proxy().redirect_stdout_to_logfile()

    # Suspend the VM (halt vCPUs), hold it down, then resume. The paused/running
    # transition reported by the monitor is the proof the VM really suspended.
    await _qemu_monitor(container, "stop")
    assert await _wait_for_run_state(
        container, "paused"
    ), f"{container} did not suspend (QEMU never reported 'paused')"
    await asyncio.sleep(SUSPEND_DURATION_S)
    await _qemu_monitor(container, "cont")
    assert await _wait_for_run_state(
        container, "running"
    ), f"{container} did not resume after 'cont'"

    assert isinstance(connection_alpha, SshConnection)
    await connection_alpha.reconnect()

    # Let the guest settle and re-establish connectivity after the suspend.
    await asyncio.sleep(SETTLE_AFTER_WAKE_S)
    await ping_between_all_nodes(env_mesh)

    # No burst either way: across this suspend the guest monotonic clock freezes
    # on some platforms (e.g. Windows QPC - a real suspend, so no ticks are even
    # missed) and jumps on others (e.g. macOS mach time - missed ticks, which the
    # Delay fix must not replay in a burst).
    consolidations_after = (await client_alpha.log.get()).count(CONSOLIDATION_LOG)
    burst = consolidations_after - consolidations_before
    assert burst <= MAX_CONSOLIDATIONS_AFTER_WAKE, (
        f"Detected a burst of {burst} WG consolidations after a VM suspend"
        f" (expected <= {MAX_CONSOLIDATIONS_AFTER_WAKE}) - see LLT-4948."
    )
