import config
from aiodocker import Docker
from contextlib import asynccontextmanager
from dataclasses import dataclass
from enum import Enum, auto
from typing import AsyncIterator, Dict, Tuple, Optional, List, Union
from utils.connection import Connection, TargetOS
from utils.connection_tracker import (
    ConnectionTracker,
    ConnectionTrackerConfig,
    FiveTuple,
    ConnectionLimits,
)
from utils.network_switcher import (
    NetworkSwitcher,
    NetworkSwitcherDocker,
    NetworkSwitcherMac,
    NetworkSwitcherWindows,
)
from utils.vm import container_util, windows_vm_util, mac_vm_util


class ConnectionTag(Enum):
    DOCKER_CONE_CLIENT_1 = auto()
    DOCKER_CONE_CLIENT_2 = auto()
    DOCKER_FULLCONE_CLIENT_1 = auto()
    DOCKER_FULLCONE_CLIENT_2 = auto()
    DOCKER_SYMMETRIC_CLIENT_1 = auto()
    DOCKER_SYMMETRIC_CLIENT_2 = auto()
    DOCKER_UPNP_CLIENT_1 = auto()
    DOCKER_UPNP_CLIENT_2 = auto()
    DOCKER_SHARED_CLIENT_1 = auto()
    DOCKER_OPEN_INTERNET_CLIENT_1 = auto()
    DOCKER_OPEN_INTERNET_CLIENT_2 = auto()
    DOCKER_OPEN_INTERNET_CLIENT_DUAL_STACK = auto()
    DOCKER_UDP_BLOCK_CLIENT_1 = auto()
    DOCKER_UDP_BLOCK_CLIENT_2 = auto()
    DOCKER_INTERNAL_SYMMETRIC_CLIENT = auto()
    WINDOWS_VM_1 = auto()
    WINDOWS_VM_2 = auto()
    MAC_VM = auto()
    DOCKER_CONE_GW_1 = auto()
    DOCKER_CONE_GW_2 = auto()
    DOCKER_CONE_GW_3 = auto()
    DOCKER_CONE_GW_4 = auto()
    DOCKER_FULLCONE_GW_1 = auto()
    DOCKER_FULLCONE_GW_2 = auto()
    DOCKER_SYMMETRIC_GW_1 = auto()
    DOCKER_SYMMETRIC_GW_2 = auto()
    DOCKER_UDP_BLOCK_GW_1 = auto()
    DOCKER_UDP_BLOCK_GW_2 = auto()
    DOCKER_UPNP_GW_1 = auto()
    DOCKER_UPNP_GW_2 = auto()
    DOCKER_VPN_1 = auto()
    DOCKER_VPN_2 = auto()
    DOCKER_NLX_1 = auto()
    DOCKER_INTERNAL_SYMMETRIC_GW = auto()


DOCKER_SERVICE_IDS: Dict[ConnectionTag, str] = {
    ConnectionTag.DOCKER_CONE_CLIENT_1: "cone-client-01",
    ConnectionTag.DOCKER_CONE_CLIENT_2: "cone-client-02",
    ConnectionTag.DOCKER_FULLCONE_CLIENT_1: "fullcone-client-01",
    ConnectionTag.DOCKER_FULLCONE_CLIENT_2: "fullcone-client-02",
    ConnectionTag.DOCKER_SYMMETRIC_CLIENT_1: "symmetric-client-01",
    ConnectionTag.DOCKER_SYMMETRIC_CLIENT_2: "symmetric-client-02",
    ConnectionTag.DOCKER_UPNP_CLIENT_1: "upnp-client-01",
    ConnectionTag.DOCKER_UPNP_CLIENT_2: "upnp-client-02",
    ConnectionTag.DOCKER_SHARED_CLIENT_1: "shared-client-01",
    ConnectionTag.DOCKER_OPEN_INTERNET_CLIENT_1: "open-internet-client-01",
    ConnectionTag.DOCKER_OPEN_INTERNET_CLIENT_2: "open-internet-client-02",
    ConnectionTag.DOCKER_OPEN_INTERNET_CLIENT_DUAL_STACK: (
        "open-internet-client-dual-stack"
    ),
    ConnectionTag.DOCKER_UDP_BLOCK_CLIENT_1: "udp-block-client-01",
    ConnectionTag.DOCKER_UDP_BLOCK_CLIENT_2: "udp-block-client-02",
    ConnectionTag.DOCKER_INTERNAL_SYMMETRIC_CLIENT: "internal-symmetric-client-01",
    ConnectionTag.DOCKER_CONE_GW_1: "cone-gw-01",
    ConnectionTag.DOCKER_CONE_GW_2: "cone-gw-02",
    ConnectionTag.DOCKER_CONE_GW_3: "cone-gw-03",
    ConnectionTag.DOCKER_CONE_GW_4: "cone-gw-04",
    ConnectionTag.DOCKER_FULLCONE_GW_1: "fullcone-gw-01",
    ConnectionTag.DOCKER_FULLCONE_GW_2: "fullcone-gw-02",
    ConnectionTag.DOCKER_SYMMETRIC_GW_1: "symmetric-gw-01",
    ConnectionTag.DOCKER_SYMMETRIC_GW_2: "symmetric-gw-02",
    ConnectionTag.DOCKER_UDP_BLOCK_GW_1: "udp-block-gw-01",
    ConnectionTag.DOCKER_UDP_BLOCK_GW_2: "udp-block-gw-02",
    ConnectionTag.DOCKER_UPNP_GW_1: "upnp-gw-01",
    ConnectionTag.DOCKER_UPNP_GW_2: "upnp-gw-02",
    ConnectionTag.DOCKER_NLX_1: "nlx-01",
    ConnectionTag.DOCKER_VPN_1: "vpn-01",
    ConnectionTag.DOCKER_VPN_2: "vpn-02",
    ConnectionTag.DOCKER_INTERNAL_SYMMETRIC_GW: "internal-symmetric-gw-01",
}


DOCKER_GW_MAP: Dict[ConnectionTag, ConnectionTag] = {
    ConnectionTag.DOCKER_CONE_CLIENT_1: ConnectionTag.DOCKER_CONE_GW_1,
    ConnectionTag.DOCKER_CONE_CLIENT_2: ConnectionTag.DOCKER_CONE_GW_2,
    ConnectionTag.DOCKER_FULLCONE_CLIENT_1: ConnectionTag.DOCKER_FULLCONE_GW_1,
    ConnectionTag.DOCKER_FULLCONE_CLIENT_2: ConnectionTag.DOCKER_FULLCONE_GW_2,
    ConnectionTag.DOCKER_SYMMETRIC_CLIENT_1: ConnectionTag.DOCKER_SYMMETRIC_GW_1,
    ConnectionTag.DOCKER_SYMMETRIC_CLIENT_2: ConnectionTag.DOCKER_SYMMETRIC_GW_2,
    ConnectionTag.DOCKER_UPNP_CLIENT_1: ConnectionTag.DOCKER_UPNP_GW_1,
    ConnectionTag.DOCKER_UPNP_CLIENT_2: ConnectionTag.DOCKER_UPNP_GW_2,
    ConnectionTag.DOCKER_SHARED_CLIENT_1: ConnectionTag.DOCKER_CONE_GW_1,
    ConnectionTag.DOCKER_UDP_BLOCK_CLIENT_1: ConnectionTag.DOCKER_UDP_BLOCK_GW_1,
    ConnectionTag.DOCKER_UDP_BLOCK_CLIENT_2: ConnectionTag.DOCKER_UDP_BLOCK_GW_2,
    ConnectionTag.WINDOWS_VM_1: ConnectionTag.DOCKER_CONE_GW_3,
    ConnectionTag.WINDOWS_VM_2: ConnectionTag.DOCKER_CONE_GW_3,
    ConnectionTag.MAC_VM: ConnectionTag.DOCKER_CONE_GW_3,
    ConnectionTag.DOCKER_OPEN_INTERNET_CLIENT_1: (
        ConnectionTag.DOCKER_OPEN_INTERNET_CLIENT_1
    ),
    ConnectionTag.DOCKER_OPEN_INTERNET_CLIENT_2: (
        ConnectionTag.DOCKER_OPEN_INTERNET_CLIENT_2
    ),
    ConnectionTag.DOCKER_OPEN_INTERNET_CLIENT_DUAL_STACK: (
        ConnectionTag.DOCKER_OPEN_INTERNET_CLIENT_DUAL_STACK
    ),
    ConnectionTag.DOCKER_INTERNAL_SYMMETRIC_CLIENT: (
        ConnectionTag.DOCKER_INTERNAL_SYMMETRIC_GW
    ),
}

LAN_ADDR_MAP: Dict[ConnectionTag, str] = {
    ConnectionTag.DOCKER_CONE_CLIENT_1: "192.168.101.104",
    ConnectionTag.DOCKER_CONE_CLIENT_2: "192.168.102.54",
    ConnectionTag.DOCKER_FULLCONE_CLIENT_1: "192.168.109.88",
    ConnectionTag.DOCKER_FULLCONE_CLIENT_2: "192.168.106.88",
    ConnectionTag.DOCKER_SYMMETRIC_CLIENT_1: "192.168.103.88",
    ConnectionTag.DOCKER_SYMMETRIC_CLIENT_2: "192.168.104.88",
    ConnectionTag.DOCKER_UPNP_CLIENT_1: "192.168.105.88",
    ConnectionTag.DOCKER_UPNP_CLIENT_2: "192.168.112.88",
    ConnectionTag.DOCKER_SHARED_CLIENT_1: "192.168.101.67",
    ConnectionTag.DOCKER_OPEN_INTERNET_CLIENT_1: "10.0.11.2",
    ConnectionTag.DOCKER_OPEN_INTERNET_CLIENT_2: "10.0.11.3",
    ConnectionTag.DOCKER_OPEN_INTERNET_CLIENT_DUAL_STACK: "10.0.11.4",
    ConnectionTag.DOCKER_UDP_BLOCK_CLIENT_1: "192.168.110.100",
    ConnectionTag.DOCKER_UDP_BLOCK_CLIENT_2: "192.168.111.100",
    ConnectionTag.DOCKER_INTERNAL_SYMMETRIC_CLIENT: "192.168.114.88",
    ConnectionTag.WINDOWS_VM_1: "10.55.0.13",
    ConnectionTag.WINDOWS_VM_2: "10.55.0.14",
    ConnectionTag.MAC_VM: "10.55.0.12",
    ConnectionTag.DOCKER_CONE_GW_1: "192.168.101.254",
    ConnectionTag.DOCKER_CONE_GW_2: "192.168.102.254",
    ConnectionTag.DOCKER_CONE_GW_3: "192.168.107.254",
    ConnectionTag.DOCKER_CONE_GW_4: "192.168.108.254",
    ConnectionTag.DOCKER_FULLCONE_GW_1: "192.168.109.254",
    ConnectionTag.DOCKER_FULLCONE_GW_2: "192.168.106.254",
    ConnectionTag.DOCKER_SYMMETRIC_GW_1: "192.168.103.254",
    ConnectionTag.DOCKER_SYMMETRIC_GW_2: "192.168.104.254",
    ConnectionTag.DOCKER_UDP_BLOCK_GW_1: "192.168.110.254",
    ConnectionTag.DOCKER_UDP_BLOCK_GW_2: "192.168.111.254",
    ConnectionTag.DOCKER_UPNP_GW_1: "192.168.105.254",
    ConnectionTag.DOCKER_UPNP_GW_2: "192.168.112.254",
    ConnectionTag.DOCKER_INTERNAL_SYMMETRIC_GW: "192.168.114.254",
    ConnectionTag.DOCKER_VPN_1: "10.0.100.1",
    ConnectionTag.DOCKER_NLX_1: "10.0.100.51",
}

LAN_ADDR_MAP_V6: Dict[ConnectionTag, str] = {
    ConnectionTag.DOCKER_OPEN_INTERNET_CLIENT_DUAL_STACK: (
        "2001:db8:85a4::dead:beef:ceed"
    ),
}


@dataclass
class ConnectionManager:
    connection: Connection
    gw_connection: Optional[Connection]
    network_switcher: NetworkSwitcher
    tracker: ConnectionTracker


def get_libtelio_binary_path(path: str, connection: Connection) -> str:
    target_os = connection.target_os
    if target_os == TargetOS.Linux:
        return config.LIBTELIO_BINARY_PATH_DOCKER + path

    if target_os == TargetOS.Windows:
        return config.LIBTELIO_BINARY_PATH_WINDOWS_VM + path

    if target_os == TargetOS.Mac:
        return config.LIBTELIO_BINARY_PATH_MAC_VM + path

    assert False, f"target_os not supported '{target_os}'"


def get_uniffi_path(connection: Connection) -> str:
    target_os = connection.target_os
    if target_os == TargetOS.Linux:
        return "/libtelio/nat-lab/tests/uniffi/libtelio_remote.py"
    if target_os == TargetOS.Windows:
        return "C:/workspace/uniffi/libtelio_remote.py".replace("/", "\\")
    if target_os == TargetOS.Mac:
        return "/var/root/workspace/uniffi/libtelio_remote.py"
    assert False, f"target_os not supported '{target_os}'"


@asynccontextmanager
async def new_connection_raw(
    tag: ConnectionTag,
    remove_existing_interfaces: bool = True,
) -> AsyncIterator[Connection]:
    if tag in DOCKER_SERVICE_IDS:
        async with Docker() as docker:
            async with container_util.get(
                docker, container_id(tag), remove_existing_interfaces
            ) as connection:
                try:
                    yield connection
                finally:
                    pass

    elif tag in [ConnectionTag.WINDOWS_VM_1, ConnectionTag.WINDOWS_VM_2]:
        async with windows_vm_util.new_connection(LAN_ADDR_MAP[tag]) as connection:
            yield connection

    elif tag == ConnectionTag.MAC_VM:
        async with mac_vm_util.new_connection() as connection:
            yield connection

    else:
        assert False, f"tag {tag} not supported"


async def create_network_switcher(
    tag: ConnectionTag, connection: Connection
) -> NetworkSwitcher:
    if tag in DOCKER_SERVICE_IDS:
        return NetworkSwitcherDocker(connection)

    if tag in [ConnectionTag.WINDOWS_VM_1, ConnectionTag.WINDOWS_VM_2]:
        return await NetworkSwitcherWindows.create(connection)

    if tag == ConnectionTag.MAC_VM:
        return NetworkSwitcherMac(connection)

    assert False, f"tag {tag} not supported"


@asynccontextmanager
async def new_connection_manager_by_tag(
    tag: ConnectionTag,
    conn_tracker_config: Optional[List[ConnectionTrackerConfig]] = None,
) -> AsyncIterator[ConnectionManager]:
    async with new_connection_raw(tag) as connection:
        network_switcher = await create_network_switcher(tag, connection)
        async with network_switcher.switch_to_primary_network():
            if tag in DOCKER_GW_MAP:
                async with new_connection_raw(DOCKER_GW_MAP[tag]) as gw_connection:
                    async with ConnectionTracker(
                        gw_connection, conn_tracker_config
                    ).run() as conn_tracker:
                        try:
                            yield ConnectionManager(
                                connection,
                                gw_connection,
                                network_switcher,
                                conn_tracker,
                            )
                        finally:
                            pass
            else:
                async with ConnectionTracker(
                    connection, conn_tracker_config
                ).run() as conn_tracker:
                    yield ConnectionManager(
                        connection, None, network_switcher, conn_tracker
                    )


@asynccontextmanager
async def new_connection_with_network_switcher(
    tag: ConnectionTag,
) -> AsyncIterator[Tuple[Connection, NetworkSwitcher]]:
    async with new_connection_manager_by_tag(tag) as conn_manager:
        yield (conn_manager.connection, conn_manager.network_switcher)


@asynccontextmanager
async def new_connection_with_conn_tracker(
    tag: ConnectionTag, conn_tracker_config: Optional[List[ConnectionTrackerConfig]]
) -> AsyncIterator[Tuple[Connection, ConnectionTracker]]:
    async with new_connection_manager_by_tag(tag, conn_tracker_config) as conn_manager:
        yield (conn_manager.connection, conn_manager.tracker)


@asynccontextmanager
async def new_connection_with_gw(
    tag: ConnectionTag,
) -> AsyncIterator[Tuple[Connection, Optional[Connection]]]:
    async with new_connection_manager_by_tag(tag) as conn_manager:
        yield (conn_manager.connection, conn_manager.gw_connection)


@asynccontextmanager
async def new_connection_with_tracker_and_gw(
    tag: ConnectionTag, conn_tracker_config: Optional[List[ConnectionTrackerConfig]]
) -> AsyncIterator[Tuple[Connection, Optional[Connection], ConnectionTracker]]:
    async with new_connection_manager_by_tag(tag, conn_tracker_config) as conn_manager:
        yield (
            conn_manager.connection,
            conn_manager.gw_connection,
            conn_manager.tracker,
        )


@asynccontextmanager
async def new_connection_by_tag(tag: ConnectionTag) -> AsyncIterator[Connection]:
    async with new_connection_manager_by_tag(tag) as conn_manager:
        yield conn_manager.connection


@asynccontextmanager
async def new_connection_with_node_tracker(
    tag: ConnectionTag,
    conn_tracker_config: Optional[List[ConnectionTrackerConfig]],
    remove_existing_interfaces: bool = True,
) -> AsyncIterator[Tuple[Connection, ConnectionTracker]]:
    if tag in DOCKER_SERVICE_IDS:
        async with new_connection_raw(tag, remove_existing_interfaces) as connection:
            network_switcher = await create_network_switcher(tag, connection)
            async with network_switcher.switch_to_primary_network():
                async with ConnectionTracker(
                    connection, conn_tracker_config
                ).run() as conn_tracker:
                    yield (connection, conn_tracker)

    else:
        assert False, f"tag {tag} not supported with node tracker"


def container_id(tag: ConnectionTag) -> str:
    if tag in DOCKER_SERVICE_IDS:
        return f"nat-lab-{DOCKER_SERVICE_IDS[tag]}-1"
    assert False, f"tag {tag} not a docker container"


def convert_port_to_integer(port: Union[str, int, None]) -> int:
    if isinstance(port, int):
        return port
    if isinstance(port, str):
        try:
            return int(port)
        except ValueError as exc:
            raise ValueError(
                f"Cannot convert string to int for port number: {port}"
            ) from exc
    else:
        raise TypeError(f"Unsupported type: {type(port)}")


def generate_connection_tracker_config(
    connection_tag,
    nlx_1_limits: ConnectionLimits = ConnectionLimits(0, 0),
    vpn_1_limits: ConnectionLimits = ConnectionLimits(0, 0),
    vpn_2_limits: ConnectionLimits = ConnectionLimits(0, 0),
    stun_limits: ConnectionLimits = ConnectionLimits(0, 0),
    stun6_limits: ConnectionLimits = ConnectionLimits(0, 0),
    ping_limits: ConnectionLimits = ConnectionLimits(0, 0),
    ping6_limits: ConnectionLimits = ConnectionLimits(0, 0),
    derp_0_limits: ConnectionLimits = ConnectionLimits(0, 0),
    derp_1_limits: ConnectionLimits = ConnectionLimits(0, 0),
    derp_2_limits: ConnectionLimits = ConnectionLimits(0, 0),
    derp_3_limits: ConnectionLimits = ConnectionLimits(0, 0),
) -> List[ConnectionTrackerConfig]:
    lan_addr = LAN_ADDR_MAP[connection_tag]
    ctc_list = [
        ConnectionTrackerConfig(
            "nlx_1",
            nlx_1_limits,
            FiveTuple(
                protocol="udp",
                src_ip=lan_addr,
                dst_ip=str(config.NLX_SERVER.get("ipv4")),
                dst_port=convert_port_to_integer(config.NLX_SERVER.get("port")),
            ),
        ),
        ConnectionTrackerConfig(
            "vpn_1",
            vpn_1_limits,
            FiveTuple(
                protocol="udp",
                src_ip=lan_addr,
                dst_ip=str(config.WG_SERVER.get("ipv4")),
                dst_port=convert_port_to_integer(config.WG_SERVER.get("port")),
            ),
        ),
        ConnectionTrackerConfig(
            "vpn_2",
            vpn_2_limits,
            FiveTuple(
                protocol="udp",
                src_ip=lan_addr,
                dst_ip=str(config.WG_SERVER_2.get("ipv4")),
                dst_port=convert_port_to_integer(config.WG_SERVER_2.get("port")),
            ),
        ),
        ConnectionTrackerConfig(
            "stun",
            stun_limits,
            FiveTuple(
                protocol="udp",
                src_ip=lan_addr,
                dst_ip=config.STUN_SERVER,
                dst_port=3478,
            ),
        ),
        ConnectionTrackerConfig("ping", ping_limits, FiveTuple(protocol="icmp")),
        ConnectionTrackerConfig("ping6", ping6_limits, FiveTuple(protocol="icmpv6")),
        ConnectionTrackerConfig(
            "derp_0",
            derp_0_limits,
            FiveTuple(
                protocol="tcp",
                src_ip=lan_addr,
                dst_ip=str(config.DERP_FAKE.get("ipv4")),
                dst_port=8765,
            ),
        ),
        ConnectionTrackerConfig(
            "derp_1",
            derp_1_limits,
            FiveTuple(
                protocol="tcp",
                src_ip=lan_addr,
                dst_ip=str(config.DERP_PRIMARY.get("ipv4")),
                dst_port=8765,
            ),
        ),
        ConnectionTrackerConfig(
            "derp_2",
            derp_2_limits,
            FiveTuple(
                protocol="tcp",
                src_ip=lan_addr,
                dst_ip=str(config.DERP_SECONDARY.get("ipv4")),
                dst_port=8765,
            ),
        ),
        ConnectionTrackerConfig(
            "derp_3",
            derp_3_limits,
            FiveTuple(
                protocol="tcp",
                src_ip=lan_addr,
                dst_ip=str(config.DERP_TERTIARY.get("ipv4")),
                dst_port=8765,
            ),
        ),
    ]

    # Add IPv6 configs
    if connection_tag in LAN_ADDR_MAP_V6:
        ctc_list.append(
            ConnectionTrackerConfig(
                "stun6",
                stun6_limits,
                FiveTuple(
                    protocol="udp",
                    src_ip=LAN_ADDR_MAP_V6[connection_tag],
                    dst_ip=config.STUNV6_SERVER,
                    dst_port=3478,
                ),
            )
        )

    return ctc_list


@asynccontextmanager
async def add_outgoing_packets_delay(
    connection: Connection, delay: str
) -> AsyncIterator:
    await remove_traffic_control_rules(connection)
    await connection.create_process([
        "tc",
        "qdisc",
        "add",
        "dev",
        "eth0",
        "root",
        "netem",
        "delay",
        delay,
    ]).execute()
    try:
        yield
    finally:
        await remove_traffic_control_rules(connection)


async def remove_traffic_control_rules(connection):
    try:
        await connection.create_process([
            "tc",
            "qdisc",
            "del",
            "dev",
            "eth0",
            "root",
            "netem",
        ]).execute()
    except:
        pass
