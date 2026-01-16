import asyncio
import base64
import itertools
import json
import logging
import os
import Pyro5  # type: ignore
import pytest
import re
import shutil
import ssl
import subprocess
import threading
import urllib.error
import urllib.request
from collections import defaultdict
from contextlib import AsyncExitStack
from datetime import datetime
from http import HTTPStatus
from itertools import combinations
from tests.config import LAN_ADDR_MAP, CORE_API_IP, CORE_API_CREDENTIALS
from tests.helpers import SetupParameters
from tests.interderp_cli import InterDerpClient
from tests.utils.bindings import TelioAdapterType
from tests.utils.connection import ConnectionTag, TargetOS, clear_ephemeral_setups_set
from tests.utils.connection.docker_connection import (
    DockerConnection,
    container_id,
    is_running,
)
from tests.utils.connection.ssh_connection import SshConnection
from tests.utils.connection_util import new_connection_raw
from tests.utils.logger import log
from tests.utils.process import ProcessExecError
from tests.utils.router import IPStack
from tests.utils.tcpdump import make_local_tcpdump, make_tcpdump
from tests.utils.testing import get_current_test_log_path
from typing import List

DERP_SERVER_1_ADDR = "http://10.0.10.1:8765"
DERP_SERVER_2_ADDR = "http://10.0.10.2:8765"
DERP_SERVER_3_ADDR = "http://10.0.10.3:8765"
DERP_SERVER_1_SECRET_KEY = "yBTYHj8yPlG9VtMYMwJSRHdzNdyAlVXGc6X2xJkjfHQ="
DERP_SERVER_2_SECRET_KEY = "2NgALOCSKJcDxwr8MtA+6lYbf7b98KSdAROGoUwZ1V0="

SETUP_CHECK_TIMEOUT_S = 30
SETUP_CHECK_RETRIES = 5
SETUP_CHECK_CONNECTIVITY_TIMEOUT = 60
SETUP_CHECK_CONNECTIVITY_RETRIES = 1
GW_CHECK_CONNECTIVITY_TIMEOUT = 30
GW_CHECK_CONNECTIVITY_RETRIES = 2
SETUP_CHECK_MAC_COLLISION_TIMEOUT_S = 300
SETUP_CHECK_MAC_COLLISION_RETRIES = 1
SETUP_CHECK_ARP_CACHE_TIMEOUT_S = 300
SETUP_CHECK_ARP_CACHE_RETRIES = 1
SETUP_CHECK_DUPLICATE_IP_TIMEOUT_S = 60
SETUP_CHECK_DUPLICATE_IP_RETRIES = 1

RUNNER: asyncio.Runner | None = None
SESSION_SCOPE_EXIT_STACK: AsyncExitStack | None = None
TASKS: List[asyncio.Task] = []
END_TASKS: threading.Event = threading.Event()

LOG_DIR = "logs"


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


async def setup_check_duplicate_ip_addresses():
    """
    Enumerate all running Docker containers, gather their IPv4 addresses (excluding 127.0.0.1),
    and fail if any IPv4 address is used by more than one container.
    Converted from nat-lab/check_ip.sh.
    """
    try:
        containers_out = subprocess.check_output(
            ["docker", "ps", "-q"], text=True
        ).strip()
    except Exception as e:  # pylint: disable=broad-exception-caught
        print(
            f"setup_check: cannot execute 'docker ps -q': {e}; skipping duplicate IP check"
        )
        return

    if not containers_out:
        print("setup_check: No running containers found.")
        return

    containers = [c for c in containers_out.splitlines() if c.strip()]

    ip_owner: dict[str, str] = {}
    duplicates: dict[str, set[str]] = defaultdict(set)

    for cid in containers:
        try:
            name = subprocess.check_output(
                ["docker", "inspect", "--format={{.Name}}", cid],
                text=True,
            ).strip()
            name = re.sub(r"^/+", "", name)
        except subprocess.CalledProcessError:
            name = cid

        # Extract IPv4 addresses inside the container without relying on grep -P.
        # Use: ip -4 -o addr show -> "... IFACE ... A.B.C.D/XX ..."
        # Then project the CIDR column and strip mask.
        try:
            ips_out = subprocess.check_output(
                [
                    "docker",
                    "exec",
                    cid,
                    "sh",
                    "-c",
                    "ip -4 -o addr show | awk '{print $4}' | cut -d/ -f1",
                ],
                text=True,
            )
        except subprocess.CalledProcessError:
            ips_out = ""

        ips = [
            ip.strip()
            for ip in ips_out.split()
            if ip.strip() and not ip.startswith("127.")
        ]

        # Print container name and IPs (for debugging parity with the original script)
        print(f"========== {name} ({cid}) ==========")
        if not ips:
            print("No IPs found")
        else:
            for ip in ips:
                print(f"IP: {ip}")
        print()

        # Detect duplicates
        for ip in ips:
            if ip in ip_owner and ip_owner[ip] != name:
                duplicates[ip].update({ip_owner[ip], name})
            else:
                ip_owner[ip] = name

    if duplicates:
        for ip, owners in sorted(duplicates.items()):
            print(
                f"  -> Duplicate IP {ip} found! Used by containers: {', '.join(sorted(owners))}"
            )
        details = {ip: sorted(list(owners)) for ip, owners in duplicates.items()}
        raise Exception(f"Found duplicate container IPv4 addresses: {details}")


async def setup_check_duplicate_mac_addresses():
    mac_re = re.compile(r"(?:[0-9a-f]{2}[:\-]){5}[0-9a-f]{2}", re.IGNORECASE)
    seen = defaultdict(set)  # mac -> set of ConnectionTag

    ignore_macs = {
        "00:00:00:00:00:00",
        "ff:ff:ff:ff:ff:ff",
    }

    async with AsyncExitStack() as exit_stack:
        for conn_tag in ConnectionTag:
            conn = await exit_stack.enter_async_context(new_connection_raw(conn_tag))

            if conn.target_os == TargetOS.Linux:
                cmd = ["sh", "-c", "ip link show | awk '/link\\/ether/ {print $2}'"]
            elif conn.target_os == TargetOS.Mac:
                cmd = ["sh", "-c", "ifconfig | awk '/ether/ {print $2}'"]
            elif conn.target_os == TargetOS.Windows:
                cmd = ["getmac", "/v", "/fo", "list"]
            else:
                raise Exception("unknown target os")

            proc = await conn.create_process(cmd).execute()
            output = proc.get_stdout()

            # extract MACs (handles both ":" and "-" formats)
            for m in mac_re.finditer(output):
                normalized = m.group(0).lower().replace("-", ":")
                if normalized in ignore_macs:
                    continue
                seen[normalized].add(conn_tag)

    duplicates = {
        mac: sorted(map(str, tags)) for mac, tags in seen.items() if len(tags) > 1
    }
    if duplicates:
        for mac, tags in duplicates.items():
            print(f"{mac} -> {', '.join(tags)}")
        raise Exception(f"Found duplicate MACs: {duplicates}")


async def setup_check_arp_cache():
    """
    Ensure all VM LAN_ADDR_MAP IPv4 addresses are present in the host ARP cache
    and are in a usable state.
    """
    if TargetOS.local() != TargetOS.Linux:
        print("setup_check: skipping ARP cache validation on non-Linux host")
        return

    def warm_arp(ip: str) -> None:
        subprocess.call(
            ["ping", "-c", "1", "-W", "1", ip],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

    def read_arp_entries() -> list[dict]:
        return json.loads(
            subprocess.check_output(["ip", "-j", "neigh", "show"], text=True).strip()
        )

    subprocess.call(["sudo", "ip", "-s", "-s", "neigh", "flush", "all"])

    acceptable_states = {"REACHABLE", "STALE", "DELAY", "PROBE", "PERMANENT"}
    failures: list[str] = []

    vm_tags = [tag for tag in ConnectionTag if tag.name.startswith("VM_")]
    for tag in vm_tags:
        if tag == ConnectionTag.VM_OPENWRT_GW_1:
            continue
        for ip in LAN_ADDR_MAP[tag].values():
            success = False
            last_arp_entries: list[dict] = []
            if ip == "":
                continue
            while True:
                if success:
                    break
                warm_arp(ip)
                last_arp_entries = read_arp_entries()
                for e in last_arp_entries:
                    dst_ip = e.get("dst")
                    lladdr = e.get("lladdr")
                    state = e.get("state")
                    if dst_ip is None or dst_ip != ip:
                        continue
                    if lladdr is None:
                        continue
                    if state is None or state[0] not in acceptable_states:
                        continue
                    success = True
                    break
            if not success:
                state = next(
                    (
                        e.get("state", "missing")
                        for e in last_arp_entries
                        if e.get("dst") == ip
                    ),
                    "missing",
                )
                failures.append(f"{tag.name}:{ip} state={state}")

    if failures:
        raise Exception("ARP cache not ready for VMs: " + ", ".join(failures))


SETUP_CHECKS = [
    (
        setup_check_duplicate_ip_addresses,
        SETUP_CHECK_DUPLICATE_IP_TIMEOUT_S,
        SETUP_CHECK_DUPLICATE_IP_RETRIES,
    ),
    (
        setup_check_arp_cache,
        SETUP_CHECK_ARP_CACHE_TIMEOUT_S,
        SETUP_CHECK_ARP_CACHE_RETRIES,
    ),
    (
        setup_check_duplicate_mac_addresses,
        SETUP_CHECK_MAC_COLLISION_TIMEOUT_S,
        SETUP_CHECK_MAC_COLLISION_RETRIES,
    ),
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
                log.warning("%s() timeout, retrying...", target)
            except ProcessExecError as e:
                log.warning("%s() process exec error %s, retrying...", target, e)
            retries -= 1
        else:
            return False

    return True


async def check_gateway_connectivity() -> bool:
    if SESSION_SCOPE_EXIT_STACK is None:
        raise RuntimeError("SESSION_SCOPE_EXIT_STACK is not initialized")
    current_gateway = None
    for _ in range(GW_CHECK_CONNECTIVITY_RETRIES + 1):
        try:
            for gw_tag in ConnectionTag:
                if "_GW" in gw_tag.name:
                    current_gateway = gw_tag
                    await SESSION_SCOPE_EXIT_STACK.enter_async_context(
                        new_connection_raw(gw_tag)
                    )
            return True
        except Exception as e:  # pylint: disable=broad-exception-caught
            gw_name = getattr(current_gateway, "name", "unknown")
            log.error("Failed to connect to %s", gw_name)
            log.error("Exception error: %s", e)
            await asyncio.sleep(GW_CHECK_CONNECTIVITY_TIMEOUT)
    # ignore connection failure in case of OpenWrt Gateway
    if current_gateway and current_gateway in [ConnectionTag.VM_OPENWRT_GW_1]:
        return True
    return False


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
        with urllib.request.urlopen(request, context=ssl_context) as response:
            if response.status == HTTPStatus.OK:
                log.debug("Service credentials cache reset successfully")
            else:
                log.warning(
                    "Failed to reset service credentials cache: HTTP %s",
                    response.status,
                )
    except urllib.error.HTTPError as e:
        log.warning(
            "Failed to reset service credentials cache: HTTP %s - %s", e.code, e.reason
        )
        raise
    except Exception as e:  # pylint: disable=broad-exception-caught
        log.warning("Error resetting service credentials cache: %s", e)
        raise


PRETEST_CLEANUPS = [
    kill_natlab_processes,
    clear_ephemeral_setups_set,
    reset_service_credentials_cache,
]


async def perform_pretest_cleanups():
    for cleanup in PRETEST_CLEANUPS:
        await cleanup()


async def _copy_vm_binaries(tag: ConnectionTag):
    try:
        log.info("Copying binaries for %s", tag)
        async with SshConnection.new_connection(
            LAN_ADDR_MAP[tag]["primary"], tag, copy_binaries=True
        ):
            pass
    except OSError as e:
        log.error(e)
        raise e


async def _copy_vm_binaries_if_needed(items):
    windows_bins_copied = False
    mac_bins_copied = False
    openwrt_bins_copied = False
    for item in items:
        for mark in item.own_markers:
            if mark.name == "windows" and not windows_bins_copied:
                await _copy_vm_binaries(ConnectionTag.VM_WINDOWS_1)
                await _copy_vm_binaries(ConnectionTag.VM_WINDOWS_2)
                windows_bins_copied = True
            elif mark.name == "mac" and not mac_bins_copied:
                await _copy_vm_binaries(ConnectionTag.VM_MAC)
                mac_bins_copied = True
            elif mark.name == "openwrt" and not openwrt_bins_copied:
                await _copy_vm_binaries(ConnectionTag.VM_OPENWRT_GW_1)
                openwrt_bins_copied = True

            if windows_bins_copied and mac_bins_copied and openwrt_bins_copied:
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
            os.path.join(LOG_DIR, f"dmesg-{suffix}.txt"), "w", encoding="utf-8"
        ) as f:
            f.write(result)


async def save_dmesg_from_remote_vm(conn_tag: ConnectionTag, suffix: str) -> None:
    os.makedirs(LOG_DIR, exist_ok=True)

    file_suffix = f"{conn_tag.name.lower()}-{suffix}"
    log_path = os.path.join(LOG_DIR, f"dmesg-{file_suffix}.txt")

    async with new_connection_raw(conn_tag) as conn:
        dmesg_cmd = ["dmesg", "-d", "-T"]
        try:
            proc = await conn.create_process(dmesg_cmd, quiet=True).execute()
            stdout = proc.get_stdout() or ""
            with open(log_path, "w", encoding="utf-8") as f:
                f.write(stdout)
        except ProcessExecError as e:
            log.warning(
                "Failed to collect remote dmesg from %s. Return code=%s, stderr=%r, stdout=%r",
                conn_tag,
                e.returncode,
                e.stderr,
                e.stdout,
            )


def save_audit_log_from_host(suffix):
    try:
        source_path = "/var/log/audit/audit.log"
        if os.path.exists(source_path):
            shutil.copy2(source_path, f"{LOG_DIR}/audit_{suffix}.log")
        else:
            log.warning("The audit file %s", source_path)
    except Exception as e:  # pylint: disable=broad-exception-caught
        log.warning("An error occurred when processing audit log: %s", e)


async def save_nordlynx_logs():
    source_log_dir_path = "/var/log"
    nlx_log_files = [
        "nlx-radius.log",
        "pq-upgrader.log",
        "fakefm.log",
        "nlx-ns.log",
        "dynamic_api_fakefm.log",
    ]

    async with new_connection_raw(ConnectionTag.VM_LINUX_NLX_1) as conn:
        for log_file in nlx_log_files:
            remote_path = os.path.join(source_log_dir_path, log_file)
            local_path = os.path.join(LOG_DIR, log_file)
            try:
                cat_proc = await conn.create_process(["cat", remote_path]).execute()
                stdout = cat_proc.get_stdout()
                with open(local_path, "w", encoding="utf-8") as f:
                    if stdout:
                        f.write(stdout)

            except Exception as e:  # pylint: disable=broad-exception-caught
                log.warning(
                    "An error occurred when processing %s log: %s", remote_path, e
                )


async def _save_macos_logs(conn, suffix):
    try:
        dmesg_proc = await conn.create_process(["dmesg"], quiet=True).execute()
        with open(
            os.path.join(LOG_DIR, f"dmesg-macos-{suffix}.txt"), "w", encoding="utf-8"
        ) as f:
            f.write(dmesg_proc.get_stdout())
    except ProcessExecError as e:
        log.warning("Failed to collect dmesg logs %s", e)


async def collect_kernel_logs(items, suffix):
    os.makedirs(LOG_DIR, exist_ok=True)

    save_dmesg_from_host(suffix)
    save_audit_log_from_host(suffix)
    await save_dmesg_from_remote_vm(ConnectionTag.VM_LINUX_NLX_1, suffix)

    for item in items:
        if any(mark.name == "mac" for mark in item.own_markers):
            try:
                async with SshConnection.new_connection(
                    LAN_ADDR_MAP[ConnectionTag.VM_MAC]["primary"], ConnectionTag.VM_MAC
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


# Session-long AsyncExitStack is created at session start and closed at session finish.
# pylint: disable=unused-argument
def pytest_sessionstart(session):
    global RUNNER, SESSION_SCOPE_EXIT_STACK
    setattr(Pyro5.config, "SERPENT_BYTES_REPR", True)
    if os.environ.get("NATLAB_SAVE_LOGS"):
        RUNNER = asyncio.Runner()
        SESSION_SCOPE_EXIT_STACK = AsyncExitStack()
        if not RUNNER.run(check_gateway_connectivity()):
            pytest.exit("Gateway nodes connectivity check failed, exiting ...")
        RUNNER.run(start_tcpdump_processes())
        RUNNER.run(start_windows_vms_resource_monitoring())


# pylint: disable=unused-argument
def pytest_sessionfinish(session, exitstatus):
    if os.environ.get("NATLAB_SAVE_LOGS") is None:
        return

    END_TASKS.set()

    if not session.config.option.collectonly:
        if RUNNER is not None and SESSION_SCOPE_EXIT_STACK is not None:
            try:
                RUNNER.run(SESSION_SCOPE_EXIT_STACK.aclose())
            finally:
                RUNNER.close()
        elif RUNNER is not None:
            RUNNER.close()
        collect_nordderper_logs()
        collect_dns_server_logs()
        collect_core_api_server_logs()
        asyncio.run(collect_kernel_logs(session.items, "after_tests"))
        asyncio.run(collect_mac_diagnostic_reports())
        asyncio.run(save_nordlynx_logs())


def collect_nordderper_logs():
    num_containers = 3

    for i in range(1, num_containers + 1):
        container_name = f"nat-lab-derp-{i:02d}-1"
        destination_path = f"{LOG_DIR}/derp_{i:02d}_relay.log"

        copy_file_from_container(
            container_name, "/etc/nordderper/relay.log", destination_path
        )


def collect_dns_server_logs():
    num_containers = 2

    for i in range(1, num_containers + 1):
        container_name = f"nat-lab-dns-server-{i}-1"
        destination_path = f"{LOG_DIR}/dns_server_{i}.log"

        copy_file_from_container(container_name, "/dns-server.log", destination_path)


def collect_core_api_server_logs():
    container_name = "nat-lab-core-api-1"
    os.makedirs(LOG_DIR, exist_ok=True)
    out_path = os.path.join(LOG_DIR, "core_api.log")
    with open(out_path, "w", encoding="utf-8") as f:
        subprocess.run(
            ["docker", "logs", container_name],
            stdout=f,
            stderr=subprocess.STDOUT,
            text=True,
            check=True,
        )


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
            LAN_ADDR_MAP[ConnectionTag.VM_MAC]["primary"], ConnectionTag.VM_MAC
        ) as connection:
            await connection.download(
                "/Library/Logs/DiagnosticReports",
                f"{LOG_DIR}/system_diagnostic_reports",
            )
            await connection.download(
                "/root/Library/Logs/DiagnosticReports",
                f"{LOG_DIR}/user_diagnostic_reports",
            )
    except Exception as e:  # pylint: disable=broad-exception-caught
        log.error("Failed to connect to the mac VM: %s", e)
        if is_ci:
            raise e


async def start_tcpdump_processes():
    if SESSION_SCOPE_EXIT_STACK is None:
        raise RuntimeError("SESSION_SCOPE_EXIT_STACK is not initialized")
    connections = []
    for gw_tag in ConnectionTag:
        if gw_tag is ConnectionTag.VM_OPENWRT_GW_1:
            continue
        if "_GW" in gw_tag.name:
            connection = await SESSION_SCOPE_EXIT_STACK.enter_async_context(
                new_connection_raw(gw_tag)
            )
            connections.append(connection)
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


async def start_windows_vms_resource_monitoring():
    vms = [ConnectionTag.DOCKER_WINDOWS_VM_1, ConnectionTag.DOCKER_WINDOWS_VM_2]
    for vm_tag in vms:
        is_vm_running = await is_running(vm_tag)
        if is_vm_running:
            start_windows_vm_resource_monitoring(vm_tag)


def start_windows_vm_resource_monitoring(vm_tag: ConnectionTag):
    def aux():
        output_filename = f"logs/cpu_usage_{vm_tag}.csv"
        log.info(
            "Starting VM resource monitoring for %s in %s", vm_tag, output_filename
        )
        with open(output_filename, "a", encoding="utf-8") as output_file:
            while not END_TASKS.is_set():
                # This command takes usually ~5s to complete, so I've decided not to add any
                # additional explicit sleep
                result = subprocess.run(
                    [
                        "docker",
                        "exec",
                        container_id(vm_tag),
                        "python3",
                        "/run/qga.py",
                        "--powershell",
                        "(Get-Counter '\\Processor(*)\\% Processor Time').CounterSamples.CookedValue",
                    ],
                    capture_output=True,
                    text=True,
                )
                lines = result.stdout.splitlines()
                lines = list(itertools.dropwhile(lambda x: "STDOUT:" not in x, lines))[
                    1:
                ]
                lines = [x.strip() for x in lines if x != ""]
                current_time_iso = datetime.now().isoformat()
                output_file.write(f"{current_time_iso}, {', '.join(lines)}\n")

    global TASKS
    TASKS += [
        asyncio.create_task(asyncio.to_thread(aux))
    ]  # Storing the task to keep it alive


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
