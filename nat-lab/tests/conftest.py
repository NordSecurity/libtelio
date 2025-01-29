import asyncio
import os
import pytest
import random
import shutil
import subprocess
from config import DERP_PRIMARY
from contextlib import AsyncExitStack
from datetime import datetime
from helpers import SetupParameters
from interderp_cli import InterDerpClient
from itertools import combinations
from typing import Dict, List, Tuple
from utils.bindings import TelioAdapterType
from utils.connection import DockerConnection
from utils.connection_util import (
    LAN_ADDR_MAP,
    ConnectionTag,
    new_connection_raw,
    new_connection_with_conn_tracker,
)
from utils.ping import ping
from utils.process import ProcessExecError
from utils.router import IPStack
from utils.tcpdump import make_tcpdump
from utils.vm import mac_vm_util, windows_vm_util

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


async def os_ephemeral_ports(vm_tag):
    async def on_output(output: str) -> None:
        print(datetime.now(), f"os_ephemeral_ports_{vm_tag}: {output}")

    start_port = random.randint(5000, 55000)
    num_ports = random.randint(2000, 5000)
    print(
        datetime.now(),
        f"Setting up ports for {vm_tag}: start={start_port}, num={num_ports}",
    )

    if vm_tag in [ConnectionTag.WINDOWS_VM_1, ConnectionTag.WINDOWS_VM_2]:
        cmd = [
            "netsh",
            "int",
            "ipv4",
            "set",
            "dynamic",
            "tcp",
            f"start={start_port}",
            f"num={num_ports}",
        ]
    elif vm_tag is ConnectionTag.MAC_VM:
        cmd = [
            "sysctl",
            "-w",
            f"net.inet.ip.portrange.first={start_port}",
            f"net.inet.ip.portrange.last={start_port + num_ports}",
        ]
    else:
        # Linux
        cmd = [
            "sysctl",
            "-w",
            f"net.ipv4.ip_local_port_range={start_port} {start_port + num_ports}",
        ]

    async with new_connection_raw(vm_tag) as connection:
        await connection.create_process(cmd).execute(on_output, on_output)


def pytest_collection_modifyitems(items):
    skip_non_asyncio = pytest.mark.skip(reason="Skipping non-dns test")
    for item in items:
        if "dns" not in item.keywords:
            item.add_marker(skip_non_asyncio)


@pytest.fixture(autouse=True)
def setup_ephemeral_ports(request):
    def execute_setup(vm_tag):
        try:
            asyncio.run(os_ephemeral_ports(vm_tag))
        except ProcessExecError as e:
            print(
                datetime.now(),
                f"os_ephemeral_ports_{vm_tag} process execution failed: {e}",
            )

    connection_tags = set()

    # Setup for all Docker clients
    connection_tags.update([
        tag
        for tag in ConnectionTag.__members__.values()
        if tag.name.startswith("DOCKER_") and "CLIENT" in tag.name
    ])

    # Handle test name (params) to search for VM tags
    test_name = request.node.name
    if "_VM_" in test_name:
        # Extract all connection tags from test name
        connection_tags.update([
            ConnectionTag[param]
            for param in test_name.split("[")[1].split("]")[0].split("-")
            if param in ConnectionTag.__members__
        ])

    # Handle test markers to search for VMs tags
    for mark in request.node.own_markers:
        if mark.name == "windows":
            connection_tags.update(
                [ConnectionTag.WINDOWS_VM_1, ConnectionTag.WINDOWS_VM_2]
            )
        elif mark.name == "mac":
            connection_tags.add(ConnectionTag.MAC_VM)

    for tag in connection_tags:
        execute_setup(tag)


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
        LAN_ADDR_MAP[ConnectionTag.WINDOWS_VM_1]: "WINDOWS_VM_1",
        LAN_ADDR_MAP[ConnectionTag.WINDOWS_VM_2]: "WINDOWS_VM_2",
        LAN_ADDR_MAP[ConnectionTag.MAC_VM]: "MAC_VM",
        DERP_PRIMARY.ipv4: "PRIMARY_DERP",
    }

    test_nodes = {
        ConnectionTag.WINDOWS_VM_1: [
            LAN_ADDR_MAP[ConnectionTag.WINDOWS_VM_2],
            LAN_ADDR_MAP[ConnectionTag.MAC_VM],
            DERP_PRIMARY.ipv4,
        ],
        ConnectionTag.WINDOWS_VM_2: [
            LAN_ADDR_MAP[ConnectionTag.WINDOWS_VM_1],
            LAN_ADDR_MAP[ConnectionTag.MAC_VM],
            DERP_PRIMARY.ipv4,
        ],
        ConnectionTag.MAC_VM: [
            LAN_ADDR_MAP[ConnectionTag.WINDOWS_VM_1],
            LAN_ADDR_MAP[ConnectionTag.WINDOWS_VM_2],
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
                print(
                    f"Failed to connect from {source} to {reverse[dest_ip]}: {repr(e)}"
                )
                print(f"Exception type: {e.__class__.__name__}")
                print(f"Exception args: {e.args}")
                print(f"Exception attributes: {dir(e)}")
                results[source].append((reverse[dest_ip], False))

    print("Connectivity between VMs (and docker):")
    for k, v in results.items():
        print(f"{k}: {v}")

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
                print(f"{target}() timeout, retrying...")
            except ProcessExecError as e:
                print(f"{target}() process exec error {e}, retrying...")
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


PRETEST_CLEANUPS = [
    kill_natlab_processes,
]


async def perform_pretest_cleanups():
    for cleanup in PRETEST_CLEANUPS:
        await cleanup()


async def _copy_vm_binaries(tag: ConnectionTag):
    if tag in [ConnectionTag.WINDOWS_VM_1, ConnectionTag.WINDOWS_VM_2]:
        try:
            print(f"copying for {tag}")
            async with windows_vm_util.new_connection(
                LAN_ADDR_MAP[tag], copy_binaries=True, reenable_nat=True
            ):
                pass
        except OSError as e:
            if os.environ.get("GITLAB_CI"):
                raise e
            print(e)
    elif tag is ConnectionTag.MAC_VM:
        try:
            async with mac_vm_util.new_connection(
                copy_binaries=True, reenable_nat=True
            ):
                pass
        except OSError as e:
            if os.environ.get("GITLAB_CI"):
                raise e
            print(e)


async def _copy_vm_binaries_if_needed(items):
    windows_bins_copied = False
    mac_bins_copied = False

    for item in items:
        for mark in item.own_markers:
            if mark.name == "windows" and not windows_bins_copied:
                await _copy_vm_binaries(ConnectionTag.WINDOWS_VM_1)
                await _copy_vm_binaries(ConnectionTag.WINDOWS_VM_2)
                windows_bins_copied = True
            elif mark.name == "mac" and not mac_bins_copied:
                await _copy_vm_binaries(ConnectionTag.MAC_VM)
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
        print(f"Error executing dmesg: {e}")
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
            print(f"The audit file {source_path} does not exist.")
    except Exception as e:  # pylint: disable=broad-exception-caught
        print(f"An error occurred when processing audit log: {e}")


async def _save_macos_logs(conn, suffix):
    try:
        dmesg_proc = await conn.create_process(["dmesg"]).execute()
        with open(
            os.path.join("logs", f"dmesg-macos-{suffix}.txt"), "w", encoding="utf-8"
        ) as f:
            f.write(dmesg_proc.get_stdout())
    except ProcessExecError as e:
        print(f"Failed to collect dmesg logs {e}")


async def collect_kernel_logs(items, suffix):
    log_dir = "logs"
    os.makedirs(log_dir, exist_ok=True)

    save_dmesg_from_host(suffix)
    save_audit_log_from_host(suffix)

    for item in items:
        if any(mark.name == "mac" for mark in item.own_markers):
            try:
                async with mac_vm_util.new_connection() as conn:
                    await _save_macos_logs(conn, suffix)
            except OSError as e:
                if os.environ.get("GITLAB_CI"):
                    raise e


def pytest_runtestloop(session):
    if not session.config.option.collectonly:
        asyncio.run(_copy_vm_binaries_if_needed(session.items))

        if os.environ.get("NATLAB_SAVE_LOGS") is not None:
            asyncio.run(collect_kernel_logs(session.items, "before_tests"))

        if not asyncio.run(perform_setup_checks()):
            pytest.exit("Setup checks failed, exiting ...")


def pytest_runtest_setup():
    asyncio.run(perform_pretest_cleanups())


# pylint: disable=unused-argument
def pytest_sessionstart(session):
    if os.environ.get("NATLAB_SAVE_LOGS") is None:
        return

    async def async_context():
        connections = [
            await SESSION_SCOPE_EXIT_STACK.enter_async_context(
                new_connection_raw(gw_tag)
            )
            for gw_tag in ConnectionTag
            if "_GW" in gw_tag.name
        ]

        connections += [
            await SESSION_SCOPE_EXIT_STACK.enter_async_context(
                new_connection_raw(conn_tag)
            )
            for conn_tag in [
                ConnectionTag.DOCKER_DNS_SERVER_1,
                ConnectionTag.DOCKER_DNS_SERVER_2,
            ]
        ]

        await SESSION_SCOPE_EXIT_STACK.enter_async_context(
            make_tcpdump(connections, session=True)
        )

    RUNNER.run(async_context())


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
        print(
            f"Log file {src_path} copied successfully from {container_name} to"
            f" {dst_path}"
        )
    except subprocess.CalledProcessError:
        print(f"Error copying log file {src_path} from {container_name} to {dst_path}")


async def collect_mac_diagnostic_reports():
    is_ci = "GITLAB_CI" in os.environ
    if not (is_ci or "NATLAB_COLLECT_MAC_DIAGNOSTIC_LOGS" in os.environ):
        return
    print("Collect mac diagnostic reports")
    try:
        async with mac_vm_util.new_connection() as connection:
            await connection.download(
                "/Library/Logs/DiagnosticReports", "logs/system_diagnostic_reports"
            )
            await connection.download(
                "/root/Library/Logs/DiagnosticReports", "logs/user_diagnostic_reports"
            )
    except Exception as e:  # pylint: disable=broad-exception-caught
        print(f"Failed to connect to the mac VM: {e}")
        if is_ci:
            raise e
