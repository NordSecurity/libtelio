import asyncio
import base64
import ntpath
import os
import pytest
import ssl
import subprocess
import urllib.error
import urllib.request
from aiodocker import Docker
from contextlib import AsyncExitStack
from http import HTTPStatus
from tests.config import (
    LAN_ADDR_MAP,
    CORE_API_IP,
    CORE_API_CREDENTIALS,
    IPERF_BINARY_WINDOWS,
    STUN_BINARY_PATH_WINDOWS,
)
from tests.conftest_helpers.setup_checks import OPENWRT_VM_TAGS
from tests.utils.connection import ConnectionTag, clear_ephemeral_setups_set
from tests.utils.connection.adb_connection import AdbConnection
from tests.utils.connection.ssh_connection import (
    SshConnection,
    CONNECT_TIMEOUT_S,
    LOGIN_TIMEOUT_S,
)
from tests.utils.connection_util import (
    new_connection_raw,
    is_running,
    running_container_names,
)
from tests.utils.logger import log, setup_log
from tests.utils.process import ProcessExecError
from tests.utils.router import IPStack, new_router
from tests.utils.tcpdump import make_tcpdump, make_local_tcpdump

# SSH connect and login, plus 5s for taskkill itself.
WINDOWS_LEFTOVER_CLEANUP_TIMEOUT_S = CONNECT_TIMEOUT_S + LOGIN_TIMEOUT_S + 5

WINDOWS_LEFTOVER_PROCESS_IMAGES = [
    "ping.exe",
    ntpath.basename(STUN_BINARY_PATH_WINDOWS),
    ntpath.basename(IPERF_BINARY_WINDOWS),
    "interderpcli.exe",
    "tcli.exe",
    "python.exe",  # All python scripts
]


async def kill_natlab_processes():
    # Do not execute cleanup in non-CI environment,
    # because cleanup requires elevated privileges,
    # and it is rather inconvenient when every run
    # requires to enter sudo password
    # If someone really wants cleanup - one can set
    # ENABLE_NATLAB_PROCESS_CLEANUP envron variable
    if (
        not "GITLAB_CI" in os.environ
        and not "ENABLE_NATLAB_PROCESS_CLEANUP" in os.environ
    ):
        return

    cleanup_script_path = os.path.join(
        os.path.dirname(__file__), "../../bin/cleanup_natlab_processes"
    )
    subprocess.run(["sudo", cleanup_script_path], check=True)


async def reset_service_credentials_cache():
    ssl_context = ssl.create_default_context()
    ssl_context.check_hostname = False
    ssl_context.verify_mode = ssl.CERT_NONE
    credentials = (
        f"{CORE_API_CREDENTIALS['username']}:{CORE_API_CREDENTIALS['password']}"
    )
    encoded_credentials = base64.b64encode(credentials.encode()).decode()
    headers = {
        "Authorization": f"Basic {encoded_credentials}",
        "Content-Type": "application/json",
        "Content-Length": "0",
    }
    request = urllib.request.Request(
        f"https://{CORE_API_IP}/test/reset-credentials",
        data=b"",
        method="POST",
        headers=headers,
    )
    try:
        with urllib.request.urlopen(
            request, context=ssl_context, timeout=5
        ) as response:
            if response.status == HTTPStatus.OK:
                setup_log.debug("Service credentials cache reset successfully")
            else:
                setup_log.warning(
                    "Failed to reset service credentials cache: HTTP %s",
                    response.status,
                )
    except urllib.error.HTTPError as e:
        setup_log.warning(
            "Failed to reset service credentials cache: HTTP %s - %s", e.code, e.reason
        )
    except Exception as e:  # pylint: disable=broad-exception-caught
        setup_log.warning("Error resetting service credentials cache: %s", e)


async def reset_upnpd_on_upnp_gateways():
    setup_log.info("Resetting miniupnpd on UPNP gateways..")
    async with AsyncExitStack() as exit_stack:
        names = await running_container_names()
        for gw_tag in ConnectionTag:
            if "UPNP_GW" not in gw_tag.name:
                continue
            try:
                if not await is_running(gw_tag, names):
                    continue
                conn = await exit_stack.enter_async_context(new_connection_raw(gw_tag))
                router = new_router(conn, IPStack.IPv4v6)
                # Briefly stop and restart miniupnpd to purge any stale mappings
                async with router.reset_upnpd():
                    pass
                setup_log.debug("miniupnpd reset on %s", gw_tag.name)
            except Exception as e:  # pylint: disable=broad-exception-caught
                setup_log.warning("Failed to reset miniupnpd on %s: %s", gw_tag.name, e)


async def reset_machines_cache():
    ssl_context = ssl.create_default_context()
    ssl_context.check_hostname = False
    ssl_context.verify_mode = ssl.CERT_NONE
    credentials = (
        f"{CORE_API_CREDENTIALS['username']}:{CORE_API_CREDENTIALS['password']}"
    )
    encoded_credentials = base64.b64encode(credentials.encode()).decode()
    headers = {
        "Authorization": f"Basic {encoded_credentials}",
        "Content-Type": "application/json",
        "Content-Length": "0",
    }
    request = urllib.request.Request(
        f"https://{CORE_API_IP}/test/reset-machines",
        data=b"",
        method="POST",
        headers=headers,
    )
    try:
        with urllib.request.urlopen(
            request, context=ssl_context, timeout=5
        ) as response:
            if response.status == HTTPStatus.OK:
                log.debug("Machines cache reset successfully")
            else:
                log.warning(
                    "Failed to reset machines cache: HTTP %s",
                    response.status,
                )
    except urllib.error.HTTPError as e:
        log.debug("Failed to reset machines cache: HTTP %s - %s", e.code, e.reason)
    except Exception as e:  # pylint: disable=broad-exception-caught
        log.debug("Could not reset machines cache (server may not be running): %s", e)


def _parse_taskkill_output(stdout: str, stderr: str) -> tuple[list[str], list[str]]:
    killed = [
        line.strip()
        for line in stdout.splitlines()
        if line.strip().upper().startswith("SUCCESS")
    ]
    errors: list[str] = []
    for line in filter(None, map(str.strip, stderr.splitlines())):
        # With /T an error may come with a "Reason: ..." line of its own.
        if errors and line.lower().startswith("reason:"):
            errors[-1] += " " + line
        else:
            errors.append(line)
    # Expected: an image that is not running, and a process that was already
    # killed as a part of its parent's tree.
    expected = ("not found", "no running instance")
    errors = [e for e in errors if not any(x in e.lower() for x in expected)]
    return killed, errors


async def _taskkill_windows_leftovers() -> tuple[list[str], list[str]]:
    command = ["taskkill", "/T", "/F"]
    for image in WINDOWS_LEFTOVER_PROCESS_IMAGES:
        command += ["/IM", image]

    async with new_connection_raw(
        ConnectionTag.VM_WINDOWS_1, prepare=False
    ) as connection:
        try:
            process = await connection.create_process(command, quiet=True).execute()
            stdout, stderr = process.get_stdout(), process.get_stderr()
        except ProcessExecError as e:
            # taskkill exits non-zero whenever any of the images is not running,
            # which is what a clean VM looks like.
            stdout, stderr = e.stdout, e.stderr
    return _parse_taskkill_output(stdout, stderr)


async def kill_windows_leftover_processes(nodeid: str):
    # An aborted test does not kill the processes it started on the Windows VM.
    try:
        killed, errors = await asyncio.wait_for(
            _taskkill_windows_leftovers(), WINDOWS_LEFTOVER_CLEANUP_TIMEOUT_S
        )
    except Exception as e:  # pylint: disable=broad-exception-caught
        setup_log.warning(
            "Failed to clean up leftover processes on the Windows VM after %s: %r",
            nodeid,
            e,
        )
        return

    if killed:
        setup_log.warning(
            "Killed %d leftover process(es) on the Windows VM after %s:\n%s",
            len(killed),
            nodeid,
            "\n".join(killed),
        )
    if errors:
        setup_log.warning(
            "Leftover process cleanup on the Windows VM after %s reported:\n%s",
            nodeid,
            "\n".join(errors),
        )


class WindowsLeftoverGuard:
    @pytest.hookimpl(hookwrapper=True)
    def pytest_runtest_teardown(
        self, item, nextitem
    ):  # pylint: disable=unused-argument
        # Fixture teardown goes first, as it normally kills the test's processes.
        # Whatever is still running after it is a leak.
        try:
            yield
        finally:
            if item.get_closest_marker("windows"):
                # Needs a new event loop: the test's one is already closed.
                asyncio.run(kill_windows_leftover_processes(item.nodeid))


PRETEST_CLEANUPS = [
    kill_natlab_processes,
    clear_ephemeral_setups_set,
    reset_service_credentials_cache,
    reset_machines_cache,
]


async def perform_pretest_cleanups(reset_upnp: bool = True):
    for cleanup in PRETEST_CLEANUPS:
        await cleanup()
    # miniupnpd only accumulates stale mappings during UPNP tests, so the reset is
    # only needed ahead of those; skipping it for everything else removes two
    # gateway round-trips from the majority of tests.
    if reset_upnp:
        await reset_upnpd_on_upnp_gateways()


async def _copy_vm_binaries(tag: ConnectionTag):
    try:
        setup_log.info("Copying binaries for %s", tag)
        async with SshConnection.new_connection(
            LAN_ADDR_MAP[tag]["primary"], tag, copy_binaries=True
        ):
            pass
    except OSError as e:
        setup_log.error(e)
        raise e


async def _copy_android_binaries(tag: ConnectionTag):
    # Android uses adb (not ssh); push the libtelio runtime into the Termux work dir.
    setup_log.info("Copying binaries for %s", tag)
    async with Docker() as docker:
        async with AdbConnection.new_connection(docker, tag, copy_binaries=True):
            pass


async def copy_vm_binaries_if_needed(session_vm_marks: set[str]):
    if "windows" in session_vm_marks:
        await _copy_vm_binaries(ConnectionTag.VM_WINDOWS_1)
    if "mac" in session_vm_marks:
        await _copy_vm_binaries(ConnectionTag.VM_MAC)
    if "openwrt" in session_vm_marks:
        for tag in OPENWRT_VM_TAGS:
            await _copy_vm_binaries(tag)
    if "android" in session_vm_marks:
        await _copy_android_binaries(ConnectionTag.VM_ANDROID_1)


async def start_tcpdump_processes(
    exit_stack: AsyncExitStack,
):
    connections = []
    names = await running_container_names()
    for gw_tag in ConnectionTag:
        if gw_tag in OPENWRT_VM_TAGS:
            continue
        if "_GW" in gw_tag.name:
            if not await is_running(gw_tag, names):
                continue
            connection = await exit_stack.enter_async_context(
                new_connection_raw(gw_tag)
            )
            connections.append(connection)
    for conn_tag in [
        ConnectionTag.DOCKER_DNS_SERVER_1,
        ConnectionTag.DOCKER_DNS_SERVER_2,
        ConnectionTag.DOCKER_DERP_1,
        ConnectionTag.DOCKER_DERP_2,
        ConnectionTag.DOCKER_DERP_3,
    ]:
        if await is_running(conn_tag, names):
            connection = await exit_stack.enter_async_context(
                new_connection_raw(conn_tag)
            )
            connections.append(connection)

    await exit_stack.enter_async_context(make_tcpdump(connections, session=True))
    await exit_stack.enter_async_context(make_local_tcpdump())
