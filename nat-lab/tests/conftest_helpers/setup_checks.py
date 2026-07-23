import asyncio
import json
import re
import tests.config
from collections import defaultdict
from contextlib import AsyncExitStack
from itertools import combinations
from tests.config import LAN_ADDR_MAP
from tests.interderp_cli import InterDerpClient
from tests.utils.connection import ConnectionTag, TargetOS
from tests.utils.connection.docker_connection import (
    DockerConnection,
    DOCKER_VM_SERVICE_IDS,
)
from tests.utils.connection_util import (
    new_connection_raw,
    is_running,
    running_container_names,
)
from tests.utils.logger import log, setup_log
from tests.utils.process import ProcessExecError
from tests.utils.tcpdump import make_tcpdump
from typing import Any, Callable, Coroutine

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
SETUP_CHECK_ARP_PER_IP_DEADLINE_S = 60
ARP_POLL_INTERVAL_S = 1.0
SETUP_CHECK_DUPLICATE_IP_TIMEOUT_S = 60
SETUP_CHECK_DUPLICATE_IP_RETRIES = 1

OPENWRT_VM_TAGS = [
    ConnectionTag.VM_OPENWRT_GW_1,
    ConnectionTag.VM_OPENWRT_GW_3,
]

SESSION_MARK_TO_CONTAINERS = {
    "fullcone": [
        ConnectionTag.VM_LINUX_FULLCONE_GW_1,
        ConnectionTag.VM_LINUX_FULLCONE_GW_2,
    ],
    "mac": [ConnectionTag.VM_MAC],
    "android": [ConnectionTag.VM_ANDROID_1],
    "nlx": [ConnectionTag.VM_LINUX_NLX_1],
    "openwrt": OPENWRT_VM_TAGS,
    "windows": [ConnectionTag.VM_WINDOWS_1],
    "windows2": [ConnectionTag.VM_WINDOWS_2],
}


async def setup_check_interderp():
    setup_log.info("Running interderp checks..")
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
            raise RuntimeError("Not docker connection")

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


async def _gather_container_ips(cid: str) -> tuple[str, list[str]]:
    proc = await asyncio.create_subprocess_exec(
        "docker",
        "inspect",
        "--format={{.Name}}",
        cid,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.DEVNULL,
    )
    stdout, _ = await proc.communicate()
    if proc.returncode == 0:
        name = re.sub(r"^/+", "", stdout.decode().strip())
    else:
        name = cid

    # Extract IPv4 addresses inside the container without relying on grep -P.
    # Use: ip -4 -o addr show -> "... IFACE ... A.B.C.D/XX ..."
    # Then project the CIDR column and strip mask.
    proc = await asyncio.create_subprocess_exec(
        "docker",
        "exec",
        cid,
        "sh",
        "-c",
        "ip -4 -o addr show | awk '{print $4}' | cut -d/ -f1",
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.DEVNULL,
    )
    stdout, _ = await proc.communicate()
    ips_out = stdout.decode() if proc.returncode == 0 else ""

    ips = [
        ip.strip() for ip in ips_out.split() if ip.strip() and not ip.startswith("127.")
    ]
    return name, ips


async def setup_check_duplicate_ip_addresses():
    """
    Enumerate all running Docker containers, gather their IPv4 addresses (excluding 127.0.0.1),
    and fail if any IPv4 address is used by more than one container.
    Converted from nat-lab/check_ip.sh.
    """
    setup_log.info("Running duplicate IP addresses check..")
    try:
        proc = await asyncio.create_subprocess_exec(
            "docker",
            "ps",
            "-q",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        stdout, _ = await proc.communicate()
        if proc.returncode != 0:
            raise RuntimeError(f"return code {proc.returncode}")
        containers_out = stdout.decode().strip()
    except Exception as e:  # pylint: disable=broad-exception-caught
        setup_log.error(
            f"cannot execute 'docker ps -q': {e}; skipping duplicate IP check"
        )
        return

    if not containers_out:
        setup_log.error("No running containers found.")
        return

    containers = [c for c in containers_out.splitlines() if c.strip()]

    ip_owner: dict[str, str] = {}
    duplicates: dict[str, set[str]] = defaultdict(set)

    for cid in containers:
        name, ips = await _gather_container_ips(cid)

        # Print container name and IPs (for debugging parity with the original script)
        setup_log.debug("========== %s (%s) ==========", name, cid)
        if not ips:
            setup_log.debug("No IPs found")
        else:
            for ip in ips:
                setup_log.debug(f"IP: {ip}")

        # Detect duplicates
        for ip in ips:
            # 100.64.0.1 is a libtelio hardcoded address representing VPN virtual peer,
            # common for every client
            if ip in ip_owner and ip_owner[ip] != name and ip != "100.64.0.1":
                duplicates[ip].update({ip_owner[ip], name})
            else:
                ip_owner[ip] = name

    if duplicates:
        for ip, owners in sorted(duplicates.items()):
            setup_log.warning(
                "  -> Duplicate IP %s found! Used by containers: %s",
                ip,
                ", ".join(sorted(owners)),
            )
        details = {ip: sorted(list(owners)) for ip, owners in duplicates.items()}
        raise RuntimeError(f"Found duplicate container IPv4 addresses: {details}")


async def _run_cmd(cmd: list[str]) -> str:
    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    stdout, stderr = await proc.communicate()
    out = (stdout or b"").decode(errors="replace")
    err = (stderr or b"").decode(errors="replace")
    return out + err


async def _dump_vm_connection_failure_diagnostics(conn_tag: ConnectionTag) -> None:
    """Dump container logs and host network state when a VM SSH connection fails.

    Helps identify whether the failure is inside the guest (sshd not ready)
    or on the host network path (routing/ARP not yet established).
    """
    if conn_tag not in DOCKER_VM_SERVICE_IDS:
        return

    container = f"nat-lab-{DOCKER_VM_SERVICE_IDS[conn_tag]}-1"
    logs = await _run_cmd(["docker", "logs", "--tail", "100", container])
    setup_log.warning("Last 100 lines of %s container logs:\n%s", container, logs)

    primary_ip = LAN_ADDR_MAP[conn_tag]["primary"]
    for cmd, label in [
        (["ping", "-c", "1", "-W", "2", primary_ip], "ping"),
        (["ip", "neigh", "show", primary_ip], "arp"),
        (["ip", "route", "get", primary_ip], "route"),
    ]:
        out = await _run_cmd(cmd)
        setup_log.warning("Host diag [%s] for %s:\n%s", label, primary_ip, out)


async def setup_check_duplicate_mac_addresses(
    session_is_container_running: dict[ConnectionTag, bool],
):
    setup_log.info("Running duplicate MAC addresses check..")
    mac_re = re.compile(r"(?:[0-9a-f]{2}[:\-]){5}[0-9a-f]{2}", re.IGNORECASE)
    seen = defaultdict(set)  # mac -> set of ConnectionTag

    ignore_macs = {
        "00:00:00:00:00:00",
        "ff:ff:ff:ff:ff:ff",
    }

    async with AsyncExitStack() as exit_stack:
        for conn_tag in ConnectionTag:
            if not session_is_container_running[conn_tag]:
                setup_log.debug(
                    "%s is not running, skipping duplicate MAC address check..",
                    conn_tag.name,
                )
                continue

            try:
                conn = await exit_stack.enter_async_context(
                    new_connection_raw(conn_tag)
                )
            except Exception as e:  # pylint: disable=broad-exception-caught
                setup_log.warning(
                    "Failed to check MAC address for %s: %s", conn_tag.name, e
                )
                await _dump_vm_connection_failure_diagnostics(conn_tag)
                raise e

            if conn.target_os in (TargetOS.Linux, TargetOS.Android):
                cmd = ["sh", "-c", "ip link show | awk '/link\\/ether/ {print $2}'"]
            elif conn.target_os == TargetOS.Mac:
                cmd = ["sh", "-c", "ifconfig | awk '/ether/ {print $2}'"]
            elif conn.target_os == TargetOS.Windows:
                cmd = ["getmac", "/v", "/fo", "list"]
            else:
                raise RuntimeError("unknown target os")

            proc = await conn.create_process(cmd, quiet=True).execute()
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
            setup_log.error("%s -> %s", mac, ", ".join(tags))
        raise RuntimeError(f"Found duplicate MACs: {duplicates}")


async def setup_check_arp_cache(session_vm_marks: set[str]):
    """
    Ensure all VM LAN_ADDR_MAP IPv4 addresses are present in the host ARP cache
    and are in a usable state.
    """
    if TargetOS.local() != TargetOS.Linux:
        setup_log.info("setup_check: skipping ARP cache validation on non-Linux host")
        return

    setup_log.info("Running ARP cache check..")

    async def warm_arp(ip: str) -> None:
        proc = await asyncio.create_subprocess_exec(
            "ping",
            "-c",
            "1",
            "-W",
            "1",
            ip,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL,
        )
        await proc.wait()

    async def read_arp_entries() -> list[dict]:
        proc = await asyncio.create_subprocess_exec(
            "ip",
            "-j",
            "neigh",
            "show",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        stdout, _ = await proc.communicate()
        if proc.returncode != 0:
            raise RuntimeError(
                f"'ip -j neigh show' failed with return code {proc.returncode}"
            )
        return json.loads(stdout)

    flush_proc = await asyncio.create_subprocess_exec(
        "sudo",
        "ip",
        "-s",
        "-s",
        "neigh",
        "flush",
        "all",
        stdout=asyncio.subprocess.DEVNULL,
        stderr=asyncio.subprocess.DEVNULL,
    )
    await flush_proc.wait()

    acceptable_states = {"REACHABLE", "STALE", "DELAY", "PROBE", "PERMANENT"}

    async def check_arp_for_ip(tag, ip: str) -> str | None:
        loop = asyncio.get_running_loop()
        deadline = loop.time() + SETUP_CHECK_ARP_PER_IP_DEADLINE_S
        last_arp_entries: list[dict] = []
        while True:
            await warm_arp(ip)
            last_arp_entries = await read_arp_entries()
            for e in last_arp_entries:
                if e.get("dst") != ip:
                    continue
                if e.get("lladdr") is None:
                    continue
                state = e.get("state")
                if state is None or state[0] not in acceptable_states:
                    continue
                return None
            if loop.time() >= deadline:
                break
            await asyncio.sleep(ARP_POLL_INTERVAL_S)
        state = next(
            (e.get("state", "missing") for e in last_arp_entries if e.get("dst") == ip),
            "missing",
        )
        return f"{tag.name}:{ip} state={state}"

    checks = [
        (tag, ip)
        for tag in get_required_vm_containers_from_marks(session_vm_marks)
        if tag not in OPENWRT_VM_TAGS
        for ip in LAN_ADDR_MAP[tag].values()
        if ip != ""
    ]
    results = await asyncio.gather(*(check_arp_for_ip(tag, ip) for tag, ip in checks))
    failures = [f for f in results if f is not None]

    if failures:
        raise RuntimeError("ARP cache not ready for VMs: " + ", ".join(failures))


async def setup_nlx_vpn_server(
    session_is_container_running: dict[ConnectionTag, bool],
) -> None:
    """Populate NLX_SERVER keys in tests.config (global, survives between tests)."""
    if not session_is_container_running.get(ConnectionTag.VM_LINUX_NLX_1, False):
        setup_log.info("NLX container is not running, skipping NLX VPN server setup..")
        return

    async with AsyncExitStack() as exit_stack:
        conn = await exit_stack.enter_async_context(
            new_connection_raw(ConnectionTag.VM_LINUX_NLX_1)
        )
        nlx_server = tests.config.NLX_SERVER
        container = nlx_server.get("container")

        get_pub_cmd = 'nlx | awk \'$1=="public" && $2=="key:" {print $3; exit}\''
        proc = await conn.create_process(["bash", "-lc", get_pub_cmd]).execute()
        pub_key = proc.get_stdout().strip()

        if not pub_key:
            raise RuntimeError(
                f"Could not obtain NordLynx public key from nlx on {container}"
            )
        nlx_server["public_key"] = pub_key
        log.debug(
            "NordLynx public key for %s: %s",
            container,
            pub_key,
        )

        get_priv_cmd = (
            "nlx showconf nlx0 | "
            'awk \'$1=="PrivateKey" && $2=="=" {print $3; exit}\''
        )

        proc_priv = await conn.create_process(["bash", "-lc", get_priv_cmd]).execute()
        priv_key = proc_priv.get_stdout().strip()

        if not priv_key:
            raise RuntimeError(
                f"Could not obtain NordLynx private key from nlx showconf on {container}"
            )

        nlx_server["private_key"] = priv_key


SETUP_CHECKS: list[tuple[Callable[..., Coroutine[Any, Any, None]], int, int]] = [
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
    (setup_nlx_vpn_server, SETUP_CHECK_TIMEOUT_S, SETUP_CHECK_RETRIES),
]


async def perform_setup_checks(
    session_is_container_running: dict[ConnectionTag, bool],
    session_vm_marks: set[str],
) -> bool:
    for target, timeout, retries in SETUP_CHECKS:
        while retries > 0:
            try:
                if target in [
                    setup_check_duplicate_mac_addresses,
                    setup_nlx_vpn_server,
                ]:
                    await asyncio.wait_for(
                        target(session_is_container_running), timeout
                    )
                elif target is setup_check_arp_cache:
                    await asyncio.wait_for(target(session_vm_marks), timeout)
                else:
                    await asyncio.wait_for(target(), timeout)
                break
            except asyncio.TimeoutError:
                setup_log.warning("%s() timeout, retrying...", target)
            except ProcessExecError as e:
                setup_log.warning("%s() process exec error %s, retrying...", target, e)
            retries -= 1
        else:
            return False

    return True


async def check_gateway_connectivity(exit_stack: AsyncExitStack) -> bool:
    setup_log.info("Checking gateways connectivity..")
    current_gateway = None
    for _ in range(GW_CHECK_CONNECTIVITY_RETRIES + 1):
        try:
            names = await running_container_names()
            for gw_tag in ConnectionTag:
                if "_GW" in gw_tag.name:
                    if not await is_running(gw_tag, names):
                        continue
                    current_gateway = gw_tag
                    await exit_stack.enter_async_context(new_connection_raw(gw_tag))
            return True
        except Exception as e:  # pylint: disable=broad-exception-caught
            gw_name = getattr(current_gateway, "name", "unknown")
            setup_log.error("Failed to connect to %s", gw_name)
            setup_log.error("Exception error: %s", e)
            await asyncio.sleep(GW_CHECK_CONNECTIVITY_TIMEOUT)
    # ignore connection failure in case of OpenWrt Gateway
    if current_gateway and current_gateway in OPENWRT_VM_TAGS:
        return True
    return False


async def check_all_containers_running() -> dict[ConnectionTag, bool]:
    result: dict[ConnectionTag, bool] = {}

    setup_log.info("Checking running containers..")

    tags = list(ConnectionTag)
    names = await running_container_names()
    is_running_results = await asyncio.gather(
        *[is_running(conn_tag, names) for conn_tag in tags]
    )

    for conn_tag, is_running_res in zip(tags, is_running_results):
        result[conn_tag] = is_running_res

    running = [tag.name for tag, status in result.items() if status]
    setup_log.debug("Running (%s): %s", len(running), ", ".join(running).lower())

    not_running = [tag.name for tag, status in result.items() if not status]
    setup_log.debug(
        "Not running (%s): %s", len(not_running), ", ".join(not_running).lower()
    )

    return result


def get_session_vm_marks(items) -> set[str]:
    session_vm_marks: set[str] = set()
    for item in items:
        for mark in item.own_markers:
            session_vm_marks.add(mark.name)
    return session_vm_marks


def get_required_vm_containers_from_marks(session_vm_marks: set[str]):
    containers = set()
    for mark in session_vm_marks:
        containers.update(SESSION_MARK_TO_CONTAINERS.get(mark, []))
    return containers
