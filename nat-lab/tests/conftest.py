import asyncio
import os
import pytest
import random
import shutil
import subprocess
from helpers import SetupParameters
from interderp_cli import InterDerpClient
from itertools import combinations
from mesh_api import start_tcpdump, stop_tcpdump
from utils.bindings import TelioAdapterType
from utils.connection import DockerConnection
from utils.connection_util import (
    ConnectionTag,
    container_id,
    DOCKER_GW_MAP,
    LAN_ADDR_MAP,
    new_connection_raw,
)
from utils.process import ProcessExecError
from utils.router import IPStack
from utils.vm import windows_vm_util, mac_vm_util

DERP_SERVER_1_ADDR = "http://10.0.10.1:8765"
DERP_SERVER_2_ADDR = "http://10.0.10.2:8765"
DERP_SERVER_3_ADDR = "http://10.0.10.3:8765"
DERP_SERVER_1_SECRET_KEY = "yBTYHj8yPlG9VtMYMwJSRHdzNdyAlVXGc6X2xJkjfHQ="
DERP_SERVER_2_SECRET_KEY = "2NgALOCSKJcDxwr8MtA+6lYbf7b98KSdAROGoUwZ1V0="

SETUP_CHECK_TIMEOUT_S = 30
SETUP_CHECK_RETRIES = 5


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


async def win_ports(vm_tag):
    async def on_output(output: str) -> None:
        print(f"win_ports_{vm_tag}: {output}")

    start_port = random.randint(5000, 55000)
    num_ports = random.randint(2000, 5000)
    print(f"Setting up ports for {vm_tag}: start={start_port}, num={num_ports}")

    async with new_connection_raw(vm_tag) as connection:
        await connection.create_process([
            "netsh",
            "int",
            "ipv4",
            "set",
            "dynamic",
            "tcp",
            "start=" + str(start_port),
            "num=" + str(num_ports),
        ]).execute(on_output, on_output)


@pytest.fixture(autouse=True)
@pytest.mark.windows
def setup_windows_ports(request):
    test_name = request.node.name

    def execute_setup(vm_tag):
        try:
            asyncio.run(win_ports(vm_tag))
        except ProcessExecError as e:
            print(f"win_ports_{vm_tag} process execution failed: {e}")

    if "[WINDOWS_VM_" in test_name:
        # Extract all VM numbers (WINDOWS_VM_1 and/or WINDOWS_VM_2)
        vm_names = [
            param
            for param in test_name.split("[")[1].split("]")[0].split("-")
            if param.startswith("WINDOWS_VM_")
        ]

        for vm_name in vm_names:
            execute_setup(ConnectionTag[vm_name])
    else:
        items = request.session.items
        for item in items:
            for mark in item.own_markers:
                if mark.name != "windows":
                    continue
                for tag in [ConnectionTag.WINDOWS_VM_1, ConnectionTag.WINDOWS_VM_2]:
                    execute_setup(tag)

                return


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


async def setup_check_interderp():
    async with new_connection_raw(ConnectionTag.DOCKER_CONE_CLIENT_1) as connection:
        if not isinstance(connection, DockerConnection):
            raise Exception("Not docker connection")
        containers = [
            connection.container_name(),
            "nat-lab-derp-01-1",
            "nat-lab-derp-02-1",
            "nat-lab-derp-03-1",
        ]
        start_tcpdump(containers)
        try:
            for idx, (server1, server2) in enumerate(
                combinations(
                    [DERP_SERVER_1_ADDR, DERP_SERVER_2_ADDR, DERP_SERVER_3_ADDR], 2
                )
            ):
                derp_test = InterDerpClient(
                    connection,
                    server1,
                    server2,
                    DERP_SERVER_1_SECRET_KEY,
                    DERP_SERVER_2_SECRET_KEY,
                    idx,
                )
                await derp_test.execute()
                await derp_test.save_logs()
        finally:
            stop_tcpdump(containers)


SETUP_CHECKS = [
    (setup_check_interderp, SETUP_CHECK_TIMEOUT_S, SETUP_CHECK_RETRIES),
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
    is_ci = os.environ.get("CUSTOM_ENV_GITLAB_CI") is not None and os.environ.get(
        "CUSTOM_ENV_GITLAB_CI"
    )
    if tag in [ConnectionTag.WINDOWS_VM_1, ConnectionTag.WINDOWS_VM_2]:
        try:
            print(f"copying for {tag}")
            async with windows_vm_util.new_connection(
                LAN_ADDR_MAP[tag], copy_binaries=True, reenable_nat=True
            ):
                pass
        except OSError as e:
            if is_ci:
                raise e
            print(e)
    elif tag is ConnectionTag.MAC_VM:
        try:
            async with mac_vm_util.new_connection(
                copy_binaries=True, reenable_nat=True
            ):
                pass
        except OSError as e:
            if is_ci:
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
    is_ci = os.environ.get("CUSTOM_ENV_GITLAB_CI") is not None and os.environ.get(
        "CUSTOM_ENV_GITLAB_CI"
    )

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
                if is_ci:
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
def pytest_runtest_call(item):
    start_tcpdump([f"nat-lab-dns-server-{i}-1" for i in range(1, 3)])


# pylint: disable=unused-argument
def pytest_runtest_makereport(item, call):
    if call.when == "call":
        stop_tcpdump([f"nat-lab-dns-server-{i}-1" for i in range(1, 3)])


# pylint: disable=unused-argument
def pytest_sessionstart(session):
    if os.environ.get("NATLAB_SAVE_LOGS") is None:
        return

    if not session.config.option.collectonly:
        start_tcpdump({container_id(gw_tag) for gw_tag in DOCKER_GW_MAP.values()})


# pylint: disable=unused-argument
def pytest_sessionfinish(session, exitstatus):
    if os.environ.get("NATLAB_SAVE_LOGS") is None:
        return

    if not session.config.option.collectonly:
        stop_tcpdump(
            {container_id(gw_tag) for gw_tag in DOCKER_GW_MAP.values()}, "./logs"
        )

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
            f"Log file {src_path} copied successfully from {container_name} to {dst_path}"
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
