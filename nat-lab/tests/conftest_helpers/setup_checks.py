import asyncio
import json
import re
import subprocess
import tests.config
from collections import defaultdict
from contextlib import AsyncExitStack
from itertools import combinations
from tests.config import LAN_ADDR_MAP
from tests.interderp_cli import InterDerpClient
from tests.utils.connection import ConnectionTag, TargetOS
from tests.utils.connection.docker_connection import DockerConnection
from tests.utils.connection_util import new_connection_raw, is_running
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
SETUP_CHECK_DUPLICATE_IP_TIMEOUT_S = 60
SETUP_CHECK_DUPLICATE_IP_RETRIES = 1

SESSION_MARK_TO_CONTAINERS = {
    "fullcone": [
        ConnectionTag.VM_LINUX_FULLCONE_GW_1,
        ConnectionTag.VM_LINUX_FULLCONE_GW_2,
    ],
    "mac": [ConnectionTag.VM_MAC],
    "nlx": [ConnectionTag.VM_LINUX_NLX_1],
    "openwrt": [ConnectionTag.VM_OPENWRT_GW_1],
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
    setup_log.info("Running duplicate IP addresses check..")
    try:
        containers_out = subprocess.check_output(
            ["docker", "ps", "-q"], text=True
        ).strip()
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
        raise Exception(f"Found duplicate container IPv4 addresses: {details}")


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
                raise e

            if conn.target_os == TargetOS.Linux:
                cmd = ["sh", "-c", "ip link show | awk '/link\\/ether/ {print $2}'"]
            elif conn.target_os == TargetOS.Mac:
                cmd = ["sh", "-c", "ifconfig | awk '/ether/ {print $2}'"]
            elif conn.target_os == TargetOS.Windows:
                cmd = ["getmac", "/v", "/fo", "list"]
            else:
                raise Exception("unknown target os")

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
        raise Exception(f"Found duplicate MACs: {duplicates}")


async def setup_check_arp_cache(session_vm_marks: set[str]):
    """
    Ensure all VM LAN_ADDR_MAP IPv4 addresses are present in the host ARP cache
    and are in a usable state.
    """
    if TargetOS.local() != TargetOS.Linux:
        setup_log.info("setup_check: skipping ARP cache validation on non-Linux host")
        return

    setup_log.info("Running ARP cache check..")

    def warm_arp(ip: str) -> None:
        subprocess.call(
            ["ping", "-c", "1", "-W", "1", ip],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

    def read_arp_entries() -> list[dict]:
        return json.loads(
            subprocess.check_output(
                ["ip", "-j", "neigh", "show"],
                text=True,
            ).strip()
        )

    subprocess.call(
        ["sudo", "ip", "-s", "-s", "neigh", "flush", "all"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    acceptable_states = {"REACHABLE", "STALE", "DELAY", "PROBE", "PERMANENT"}
    failures: list[str] = []

    for tag in get_required_vm_containers_from_marks(session_vm_marks):
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


async def setup_nlx_vpn_server() -> None:
    """Populate NLX_SERVER keys in tests.config (global, survives between tests)."""
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
                if target is setup_check_duplicate_mac_addresses:
                    await asyncio.wait_for(
                        asyncio.shield(target(session_is_container_running)), timeout
                    )
                elif target is setup_check_arp_cache:
                    await asyncio.wait_for(
                        asyncio.shield(target(session_vm_marks)), timeout
                    )
                else:
                    await asyncio.wait_for(asyncio.shield(target()), timeout)
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
            for gw_tag in ConnectionTag:
                if "_GW" in gw_tag.name:
                    if not await is_running(gw_tag):
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
    if current_gateway and current_gateway in [ConnectionTag.VM_OPENWRT_GW_1]:
        return True
    return False


async def check_all_containers_running() -> dict[ConnectionTag, bool]:
    result: dict[ConnectionTag, bool] = {}

    setup_log.info("Checking running containers..")

    tags = list(ConnectionTag)
    is_running_results = await asyncio.gather(
        *[is_running(conn_tag) for conn_tag in tags]
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
