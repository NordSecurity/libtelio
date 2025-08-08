import asyncio
import logging
import os
import pytest
import shutil
import subprocess
from config import DERP_PRIMARY, LAN_ADDR_MAP
from contextlib import AsyncExitStack
from helpers import SetupParameters
from interderp_cli import InterDerpClient
from itertools import combinations
from typing import Dict, List, Tuple
from utils.bindings import TelioAdapterType
from utils.connection import ConnectionTag, clear_ephemeral_setups_set
from utils.connection.docker_connection import DockerConnection
from utils.connection.ssh_connection import SshConnection
from utils.connection_util import new_connection_raw, new_connection_with_conn_tracker
from utils.logger import log
from utils.ping import ping
from utils.process import ProcessExecError
from utils.router import IPStack
from utils.tcpdump import make_tcpdump, make_local_tcpdump
from utils.testing import get_current_test_log_path

DERP_SERVER_1_ADDR = "http://10.0.10.1:8765"
DERP_SERVER_2_ADDR = "http://10.0.10.2:8765"
DERP_SERVER_3_ADDR = "http://10.0.10.3:8765"
DERP_SERVER_1_SECRET_KEY = "yBTYHj8yPlG9VtMYMwJSRHdzNdyAlVXGc6X2xJkjfHQ="
DERP_SERVER_2_SECRET_KEY = "2NgALOCSKJcDxwr8MtA+6lYbf7b98KSdAROGoUwZ1V0="

SETUP_CHECK_TIMEOUT_S = 30
SETUP_CHECK_RETRIES = 5
SETUP_CHECK_CONNECTIVITY_TIMEOUT = 60
SETUP_CHECK_CONNECTIVITY_RETRIES = 1

RUNNER = asyncio.Runner()
# pylint: disable=unnecessary-dunder-call
SESSION_SCOPE_EXIT_STACK = RUNNER.run(AsyncExitStack().__aenter__())


def _cancel_all_tasks(loop: asyncio.AbstractEventLoop):
    to_cancel = asyncio.tasks.all_tasks(loop)
    if not to_cancel:
        return

    for task in to_cancel:
        task.print_stack()
        task.cancel()

    loop.run_until_complete(asyncio.tasks.gather(*to_cancel, return_exceptions=True))

    for task in to_cancel:
        if task.cancelled():
            continue
        if task.exception() is not None:
            loop.call_exception_handler({
                "message": "unhandled exception during asyncio.run() shutdown",
                "exception": task.exception(),
                "task": task,
            })


@pytest.fixture(scope="function")
def event_loop():
    loop = asyncio.get_event_loop_policy().new_event_loop()
    try:
        yield loop
    finally:
        try:
            _cancel_all_tasks(loop)
            loop.run_until_complete(loop.shutdown_asyncgens())
            loop.run_until_complete(loop.shutdown_default_executor())
        finally:
            asyncio.events.set_event_loop(None)
            loop.close()


# Keep in mind that Windows can consider the filesize too big if parameters are not stripped
def pytest_make_parametrize_id(config, val):
    param_id = ""
    if isinstance(val, (list, tuple)):
        for v in val:
            res = pytest_make_parametrize_id(config, v)
            if isinstance(res, str) and res != "":
                param_id += f"-{res}"
        param_id = f"{param_id[1:]}"
    elif isinstance(val, (SetupParameters,)):
        short_conn_tag_name = val.connection_tag.name.removeprefix("DOCKER_")
        param_id = f"{short_conn_tag_name}-{val.adapter_type_override.name.replace('_', '') if val.adapter_type_override is not None else ''}"
        if (
            val.features.direct is not None
            and val.features.direct.providers is not None
        ):
            for provider in val.features.direct.providers:
                param_id += f"-{provider.name}"

        if val.features.batching is not None:
            param_id += (
                f"-batch-{str(val.features.batching.direct_connection_threshold)}"
            )
    elif isinstance(val, (ConnectionTag,)):
        param_id = val.name.removeprefix("DOCKER_")
    elif isinstance(val, (TelioAdapterType,)):
        param_id = val.name.replace("_", "")
    elif isinstance(val, IPStack):
        if val == IPStack.IPv4:
            param_id = "IPv4"
        elif val == IPStack.IPv4v6:
            param_id = "IPv4v6"
        elif val == IPStack.IPv6:
            param_id = "IPv6"
    elif isinstance(val, str):
        if len(val) > 16:
            param_id = f"{val[:14]}.."
        else:
            param_id = val
    else:
        return None
    return param_id


async def setup_check_connectivity():
    if "GITLAB_CI" not in os.environ:
        return

    reverse: Dict[str, str] = {
        LAN_ADDR_MAP[ConnectionTag.VM_WINDOWS_1]: "VM_WINDOWS_1",
        LAN_ADDR_MAP[ConnectionTag.VM_WINDOWS_2]: "VM_WINDOWS_2",
        LAN_ADDR_MAP[ConnectionTag.VM_MAC]: "VM_MAC",
        DERP_PRIMARY.ipv4: "PRIMARY_DERP",
    }

    test_nodes = {
        ConnectionTag.VM_WINDOWS_1: [
            LAN_ADDR_MAP[ConnectionTag.VM_WINDOWS_2],
            LAN_ADDR_MAP[ConnectionTag.VM_MAC],
            DERP_PRIMARY.ipv4,
        ],
        ConnectionTag.VM_WINDOWS_2: [
            LAN_ADDR_MAP[ConnectionTag.VM_WINDOWS_1],
            LAN_ADDR_MAP[ConnectionTag.VM_MAC],
            DERP_PRIMARY.ipv4,
        ],
        ConnectionTag.VM_MAC: [
            LAN_ADDR_MAP[ConnectionTag.VM_WINDOWS_1],
            LAN_ADDR_MAP[ConnectionTag.VM_WINDOWS_2],
            DERP_PRIMARY.ipv4,
        ],
    }
    results: Dict[ConnectionTag, List[Tuple[str, bool]]] = {
        key: [] for key in test_nodes
    }
    for source, destinations in test_nodes.items():
        for dest_ip in destinations:
            try:
                async with new_connection_with_conn_tracker(source, None) as (
                    connection,
                    _,
                ):
                    await ping(connection, dest_ip, 5)
                    results[source].append((reverse[dest_ip], True))
            except Exception as e:  # pylint: disable=broad-exception-caught
                log.error(
                    "Failed to connect from %s to %s: %s",
                    source,
                    reverse[dest_ip],
                    repr(e),
                )
                log.error("Exception type: %s", e.__class__.__name__)
                log.error("Exception args: %s", e.args)
                log.error("Exception attributes: %s", dir(e))
                results[source].append((reverse[dest_ip], False))

    log.info("Connectivity between VMs (and docker):")
    for k, v in results.items():
        log.info("%s: %s", k, v)

    for k, v in results.items():
        for dest_ip, status in v:
            assert status, f"Failed to connect from {k} to {dest_ip}"


async def setup_check_interderp():
    async with AsyncExitStack() as exit_stack:
        connections = [
            await exit_stack.enter_async_context(new_connection_raw(conn_tag))
            for conn_tag in [
                ConnectionTag.DOCKER_CONE_CLIENT_1,
                ConnectionTag.DOCKER_DERP_1,
                ConnectionTag.DOCKER_DERP_2,
                ConnectionTag.DOCKER_DERP_3,
            ]
        ]

        if not isinstance(connections[0], DockerConnection):
            raise Exception("Not docker connection")

        async with make_tcpdump(connections):
            for idx, (server1, server2) in enumerate(
                combinations(
                    [DERP_SERVER_1_ADDR, DERP_SERVER_2_ADDR, DERP_SERVER_3_ADDR], 2
                )
            ):
                derp_test = InterDerpClient(
                    connections[0],
                    server1,
                    server2,
                    DERP_SERVER_1_SECRET_KEY,
                    DERP_SERVER_2_SECRET_KEY,
                    idx,
                )
                await derp_test.execute()
                await derp_test.save_logs()


SETUP_CHECKS = [
    (setup_check_interderp, SETUP_CHECK_TIMEOUT_S, SETUP_CHECK_RETRIES),
    (
        setup_check_connectivity,
        SETUP_CHECK_CONNECTIVITY_TIMEOUT,
        SETUP_CHECK_CONNECTIVITY_RETRIES,
    ),
]


async def perform_setup_checks() -> bool:
    if "NATLAB_SKIP_SETUP_CHECKS" in os.environ:
        return True

    for target, timeout, retries in SETUP_CHECKS:
        while retries > 0:
            try:
                await asyncio.wait_for(asyncio.shield(target()), timeout)
                break
            except asyncio.TimeoutError:
                log.warning("%s() timeout, retrying...", target)
            except ProcessExecError as e:
                log.warning("%s() process exec error %s, retrying...", target, e)
            retries -= 1
        else:
            return False

    return True


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
        os.path.dirname(__file__), "../bin/cleanup_natlab_processes"
    )
    subprocess.run(["sudo", cleanup_script_path]).check_returncode()


PRETEST_CLEANUPS = [kill_natlab_processes, clear_ephemeral_setups_set]


async def perform_pretest_cleanups():
    for cleanup in PRETEST_CLEANUPS:
        await cleanup()


async def _copy_vm_binaries(tag: ConnectionTag):
    try:
        log.info("Copying binaries for %s", tag)
        async with SshConnection.new_connection(
            LAN_ADDR_MAP[tag], tag, copy_binaries=True
        ):
            pass
    except OSError as e:
        log.error(e)
        raise e


async def _copy_vm_binaries_if_needed(items):
    windows_bins_copied = False
    mac_bins_copied = False

    for item in items:
        for mark in item.own_markers:
            if mark.name == "windows" and not windows_bins_copied:
                await _copy_vm_binaries(ConnectionTag.VM_WINDOWS_1)
                await _copy_vm_binaries(ConnectionTag.VM_WINDOWS_2)
                windows_bins_copied = True
            elif mark.name == "mac" and not mac_bins_copied:
                await _copy_vm_binaries(ConnectionTag.VM_MAC)
                mac_bins_copied = True

            if windows_bins_copied and mac_bins_copied:
                return


def save_dmesg_from_host(suffix):
    try:
        result = subprocess.run(
            ["sudo", "dmesg", "-d", "-T"],
            capture_output=True,
            text=True,
            check=True,
        ).stdout
    except subprocess.CalledProcessError as e:
        log.error("Error executing dmesg: %s", e)
        return

    if result:
        with open(
            os.path.join("logs", f"dmesg-{suffix}.txt"), "w", encoding="utf-8"
        ) as f:
            f.write(result)


def save_audit_log_from_host(suffix):
    try:
        source_path = "/var/log/audit/audit.log"
        if os.path.exists(source_path):
            shutil.copy2(source_path, f"logs/audit_{suffix}.log")
        else:
            log.warning("The audit file %s", source_path)
    except Exception as e:  # pylint: disable=broad-exception-caught
        log.warning("An error occurred when processing audit log: %s", e)


async def save_fakefm_logs():
    async with new_connection_raw(ConnectionTag.DOCKER_NLX_1) as conn:
        try:
            source_path = "/var/log/fakefm.log"
            local_path = os.path.join("logs", "fakefm.log")
            await conn.download(source_path, local_path)
        except Exception as e:  # pylint: disable=broad-exception-caught
            print(f"An error occurred when processing fakefm log: {e}")


async def _save_macos_logs(conn, suffix):
    try:
        dmesg_proc = await conn.create_process(["dmesg"], quiet=True).execute()
        with open(
            os.path.join("logs", f"dmesg-macos-{suffix}.txt"), "w", encoding="utf-8"
        ) as f:
            f.write(dmesg_proc.get_stdout())
    except ProcessExecError as e:
        log.warning("Failed to collect dmesg logs %s", e)


async def collect_kernel_logs(items, suffix):
    log_dir = "logs"
    os.makedirs(log_dir, exist_ok=True)

    save_dmesg_from_host(suffix)
    save_audit_log_from_host(suffix)

    for item in items:
        if any(mark.name == "mac" for mark in item.own_markers):
            try:
                async with SshConnection.new_connection(
                    LAN_ADDR_MAP[ConnectionTag.VM_MAC], ConnectionTag.VM_MAC
                ) as conn:
                    await _save_macos_logs(conn, suffix)
            except OSError as e:
                if os.environ.get("GITLAB_CI"):
                    raise e


def pytest_runtestloop(session):
    if not session.config.option.collectonly:
        if not asyncio.run(perform_setup_checks()):
            pytest.exit("Setup checks failed, exiting ...")

        if os.environ.get("NATLAB_SAVE_LOGS") is not None:
            asyncio.run(collect_kernel_logs(session.items, "before_tests"))

        asyncio.run(_copy_vm_binaries_if_needed(session.items))


def pytest_runtest_setup():
    asyncio.run(perform_pretest_cleanups())


# pylint: disable=unused-argument
def pytest_sessionstart(session):
    if os.environ.get("NATLAB_SAVE_LOGS"):
        RUNNER.run(start_tcpdump_processes())


# pylint: disable=unused-argument
def pytest_sessionfinish(session, exitstatus):
    if os.environ.get("NATLAB_SAVE_LOGS") is None:
        return

    if not session.config.option.collectonly:
        RUNNER.close()
        collect_nordderper_logs()
        collect_dns_server_logs()
        asyncio.run(collect_kernel_logs(session.items, "after_tests"))
        asyncio.run(collect_mac_diagnostic_reports())
        asyncio.run(save_fakefm_logs())


def collect_nordderper_logs():
    num_containers = 3

    for i in range(1, num_containers + 1):
        container_name = f"nat-lab-derp-{i:02d}-1"
        destination_path = f"logs/derp_{i:02d}_relay.log"

        copy_file_from_container(
            container_name, "/etc/nordderper/relay.log", destination_path
        )


def collect_dns_server_logs():
    num_containers = 2

    for i in range(1, num_containers + 1):
        container_name = f"nat-lab-dns-server-{i}-1"
        destination_path = f"logs/dns_server_{i}.log"

        copy_file_from_container(container_name, "/dns-server.log", destination_path)


def copy_file_from_container(container_name, src_path, dst_path):
    docker_cp_command = f"docker cp {container_name}:{src_path} {dst_path}"
    try:
        subprocess.run(docker_cp_command, shell=True, check=True)
        log.info(
            "Log file %s copied successfully from %s to %s",
            src_path,
            container_name,
            dst_path,
        )
    except subprocess.CalledProcessError:
        log.warning(
            "Error copying log file %s from %s to %s",
            src_path,
            container_name,
            dst_path,
        )


async def collect_mac_diagnostic_reports():
    is_ci = "GITLAB_CI" in os.environ
    if not (is_ci or "NATLAB_COLLECT_MAC_DIAGNOSTIC_LOGS" in os.environ):
        return
    log.info("Collect mac diagnostic reports")
    try:
        async with SshConnection.new_connection(
            LAN_ADDR_MAP[ConnectionTag.VM_MAC], ConnectionTag.VM_MAC
        ) as connection:
            await connection.download(
                "/Library/Logs/DiagnosticReports", "logs/system_diagnostic_reports"
            )
            await connection.download(
                "/root/Library/Logs/DiagnosticReports", "logs/user_diagnostic_reports"
            )
    except Exception as e:  # pylint: disable=broad-exception-caught
        log.error("Failed to connect to the mac VM: %s", e)
        if is_ci:
            raise e


async def start_tcpdump_processes():
    connections = [
        await SESSION_SCOPE_EXIT_STACK.enter_async_context(new_connection_raw(gw_tag))
        for gw_tag in ConnectionTag
        if "_GW" in gw_tag.name
    ]
    connections += [
        await SESSION_SCOPE_EXIT_STACK.enter_async_context(new_connection_raw(conn_tag))
        for conn_tag in [
            ConnectionTag.DOCKER_DNS_SERVER_1,
            ConnectionTag.DOCKER_DNS_SERVER_2,
        ]
    ]

    await SESSION_SCOPE_EXIT_STACK.enter_async_context(
        make_tcpdump(connections, session=True)
    )
    await SESSION_SCOPE_EXIT_STACK.enter_async_context(make_local_tcpdump())


@pytest.fixture(autouse=True)
def setup_logger(tmp_path, request):
    file_handler = None
    if os.environ.get("NATLAB_SAVE_LOGS"):
        log_dir = get_current_test_log_path()
        os.makedirs(log_dir, exist_ok=True)
        log_file = os.path.join(log_dir, "debug.log")

        file_handler = logging.FileHandler(log_file, mode="w")
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(
            logging.Formatter("%(asctime)s,%(msecs)03d | %(levelname)s %(message)s")
        )
        log.addHandler(file_handler)

    try:
        yield
    finally:
        if file_handler:
            file_handler.flush()
            log.removeHandler(file_handler)
            file_handler.close()
        else:
            pass
