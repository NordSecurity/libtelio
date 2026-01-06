from aiodocker import Docker
from contextlib import asynccontextmanager
from dataclasses import dataclass
from tests import config
from tests.config import LAN_ADDR_MAP, LAN_ADDR_MAP_V6
from tests.utils.connection import Connection, TargetOS, ConnectionTag
from tests.utils.connection.docker_connection import (
    DockerConnection,
    DOCKER_GW_MAP,
    DOCKER_SERVICE_IDS,
)
from tests.utils.connection.ssh_connection import SshConnection
from tests.utils.connection_tracker import (
    ConnTrackerEventsValidator,
    ConnectionTracker,
    ConnectionCountLimit,
    FiveTuple,
)
from tests.utils.network_switcher import (
    Interface,
    NetworkSwitcher,
    NetworkSwitcherDocker,
    NetworkSwitcherMac,
    NetworkSwitcherWindows,
    NetworkSwitcherOpenwrt,
    NetworkSwitcherLinux,
)
from typing import AsyncIterator, Tuple, Optional, List, Union

IS_VM_RUNNING_PING_TIMEOUT = 10.0


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
        return config.LIBTELIO_BINARY_PATH_VM_MAC + path

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
) -> AsyncIterator[Connection]:
    try:
        if tag in DOCKER_SERVICE_IDS:
            async with Docker() as docker:
                async with DockerConnection.new_connection(docker, tag) as connection:
                    yield connection
        elif is_tag_valid_for_ssh_connection(tag):
            async with SshConnection.new_connection(
                LAN_ADDR_MAP[tag]["primary"], tag
            ) as connection:
                yield connection
        else:
            assert False, f"Tag {tag} not supported"
    finally:
        pass


async def create_network_switcher(
    tag: ConnectionTag, connection: Connection
) -> NetworkSwitcher:
    if tag in DOCKER_SERVICE_IDS:
        return NetworkSwitcherDocker(connection)
    if tag in [ConnectionTag.VM_WINDOWS_1, ConnectionTag.VM_WINDOWS_2]:
        return await NetworkSwitcherWindows.create(connection)
    if tag == ConnectionTag.VM_MAC:
        return NetworkSwitcherMac(connection)
    if tag == ConnectionTag.VM_OPENWRT_GW_1:
        return NetworkSwitcherOpenwrt(connection)
    if tag in [
        ConnectionTag.VM_LINUX_NLX_1,
        ConnectionTag.VM_LINUX_FULLCONE_GW_1,
        ConnectionTag.VM_LINUX_FULLCONE_GW_2,
    ]:
        return NetworkSwitcherLinux(connection)

    assert False, f"tag {tag} not supported"


@asynccontextmanager
async def new_connection_manager_by_tag(
    tag: ConnectionTag,
    conn_tracker_config: Optional[List[ConnTrackerEventsValidator]] = None,
) -> AsyncIterator[ConnectionManager]:
    async with new_connection_raw(tag) as connection:
        network_switcher = await create_network_switcher(tag, connection)
        await network_switcher.switch_to_primary_network()
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
async def new_connection_with_conn_tracker(
    tag: ConnectionTag,
    conn_tracker_config: Optional[List[ConnTrackerEventsValidator]],
) -> AsyncIterator[Tuple[Connection, ConnectionTracker]]:
    async with new_connection_manager_by_tag(tag, conn_tracker_config) as conn_manager:
        yield (conn_manager.connection, conn_manager.tracker)


@asynccontextmanager
async def new_connection_by_tag(tag: ConnectionTag) -> AsyncIterator[Connection]:
    async with new_connection_manager_by_tag(tag, None) as conn_manager:
        yield conn_manager.connection


@asynccontextmanager
async def new_connection_with_node_tracker(
    tag: ConnectionTag,
    conn_tracker_config: Optional[List[ConnTrackerEventsValidator]],
) -> AsyncIterator[Tuple[Connection, ConnectionTracker]]:
    if tag in DOCKER_SERVICE_IDS:
        async with new_connection_raw(tag) as connection:
            network_switcher = await create_network_switcher(tag, connection)
            await network_switcher.switch_to_primary_network()
            async with ConnectionTracker(
                connection, conn_tracker_config
            ).run() as conn_tracker:
                yield (connection, conn_tracker)
    else:
        assert False, f"tag {tag} not supported with node tracker"


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
    nlx_1_limits: tuple[Optional[int], Optional[int]] = (0, 0),
    vpn_1_limits: tuple[Optional[int], Optional[int]] = (0, 0),
    vpn_2_limits: tuple[Optional[int], Optional[int]] = (0, 0),
    stun_limits: tuple[Optional[int], Optional[int]] = (0, 0),
    stun6_limits: tuple[Optional[int], Optional[int]] = (0, 0),
    ping_limits: tuple[Optional[int], Optional[int]] = (0, 0),
    ping6_limits: tuple[Optional[int], Optional[int]] = (0, 0),
    derp_0_limits: tuple[Optional[int], Optional[int]] = (0, 0),
    derp_1_limits: tuple[Optional[int], Optional[int]] = (0, 0),
    derp_2_limits: tuple[Optional[int], Optional[int]] = (0, 0),
    derp_3_limits: tuple[Optional[int], Optional[int]] = (0, 0),
) -> List[ConnTrackerEventsValidator]:
    lan_addr = LAN_ADDR_MAP[connection_tag]["primary"]
    ctc_list = [
        ConnectionCountLimit.create_with_tuple(
            "nlx_1",
            nlx_1_limits,
            FiveTuple(
                protocol="udp",
                src_ip=lan_addr,
                dst_ip=str(config.NLX_SERVER.get("ipv4")),
                dst_port=convert_port_to_integer(config.NLX_SERVER.get("port")),
            ),
        ),
        ConnectionCountLimit.create_with_tuple(
            "vpn_1",
            vpn_1_limits,
            FiveTuple(
                protocol="udp",
                src_ip=lan_addr,
                dst_ip=str(config.WG_SERVER.get("ipv4")),
                dst_port=convert_port_to_integer(config.WG_SERVER.get("port")),
            ),
        ),
        ConnectionCountLimit.create_with_tuple(
            "vpn_2",
            vpn_2_limits,
            FiveTuple(
                protocol="udp",
                src_ip=lan_addr,
                dst_ip=str(config.WG_SERVER_2.get("ipv4")),
                dst_port=convert_port_to_integer(config.WG_SERVER_2.get("port")),
            ),
        ),
        ConnectionCountLimit.create_with_tuple(
            "stun",
            stun_limits,
            FiveTuple(
                protocol="udp",
                src_ip=lan_addr,
                dst_ip=config.STUN_SERVER,
                dst_port=3478,
            ),
        ),
        ConnectionCountLimit.create_with_tuple(
            "ping", ping_limits, FiveTuple(protocol="icmp")
        ),
        ConnectionCountLimit.create_with_tuple(
            "ping6", ping6_limits, FiveTuple(protocol="icmpv6")
        ),
        ConnectionCountLimit.create_with_tuple(
            "derp_0",
            derp_0_limits,
            FiveTuple(
                protocol="tcp",
                src_ip=lan_addr,
                dst_ip=str(config.DERP_FAKE.ipv4),
                dst_port=8765,
            ),
        ),
        ConnectionCountLimit.create_with_tuple(
            "derp_1",
            derp_1_limits,
            FiveTuple(
                protocol="tcp",
                src_ip=lan_addr,
                dst_ip=str(config.DERP_PRIMARY.ipv4),
                dst_port=8765,
            ),
        ),
        ConnectionCountLimit.create_with_tuple(
            "derp_2",
            derp_2_limits,
            FiveTuple(
                protocol="tcp",
                src_ip=lan_addr,
                dst_ip=str(config.DERP_SECONDARY.ipv4),
                dst_port=8765,
            ),
        ),
        ConnectionCountLimit.create_with_tuple(
            "derp_3",
            derp_3_limits,
            FiveTuple(
                protocol="tcp",
                src_ip=lan_addr,
                dst_ip=str(config.DERP_TERTIARY.ipv4),
                dst_port=8765,
            ),
        ),
    ]

    # Add IPv6 configs
    if connection_tag in LAN_ADDR_MAP_V6:
        ctc_list.append(
            ConnectionCountLimit.create_with_tuple(
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
    await connection.create_process(
        [
            "tc",
            "qdisc",
            "add",
            "dev",
            "eth0",
            "root",
            "netem",
            "delay",
            delay,
        ],
        quiet=True,
    ).execute()
    try:
        yield
    finally:
        await remove_traffic_control_rules(connection)


async def remove_traffic_control_rules(connection):
    try:
        await connection.create_process(
            [
                "tc",
                "qdisc",
                "del",
                "dev",
                "eth0",
                "root",
                "netem",
            ],
            quiet=True,
        ).execute()
    except:
        pass


def is_tag_valid_for_ssh_connection(tag: ConnectionTag) -> bool:
    return tag in [
        ConnectionTag.VM_WINDOWS_1,
        ConnectionTag.VM_WINDOWS_2,
        ConnectionTag.VM_MAC,
        ConnectionTag.VM_OPENWRT_GW_1,
        ConnectionTag.VM_LINUX_NLX_1,
        ConnectionTag.VM_LINUX_FULLCONE_GW_1,
        ConnectionTag.VM_LINUX_FULLCONE_GW_2,
    ]


# This function stems from the fact that pytest connection with VMs and libtelio instances
#  - through FFI (remote/proxy.py) - always rely on the primary interface so disabling it becomes non practical.
async def set_secondary_ifc_state(
    connection: Connection, enable: bool, secondary_ifc: Optional[Interface] = None
) -> Optional[Interface]:
    if connection.target_os == TargetOS.Linux:
        await connection.create_process([
            "ip",
            "link",
            "set",
            "eth1",
            "up" if enable else "down",
        ]).execute()
    elif connection.target_os == TargetOS.Mac:
        await connection.create_process([
            "ifconfig",
            "eth1",
            "up" if enable else "down",
        ]).execute()
    elif connection.target_os == TargetOS.Windows:
        if not secondary_ifc:
            interfaces = await Interface.get_enabled_network_interfaces(connection)
            for interface in interfaces:
                if interface.ipv4:
                    if (
                        interface.ipv4
                        == config.LAN_ADDR_MAP[connection.tag]["secondary"]
                    ):
                        secondary_ifc = interface
        assert secondary_ifc, LookupError("Couldn't find secondary interface")
        if enable:
            await secondary_ifc.enable(connection)
        else:
            await secondary_ifc.disable(connection)
        return secondary_ifc

    # TODO: Create Interface class for Linux/Macos, until then secondary ifc ("eth1") is hardcoded
    return None


@asynccontextmanager
async def toggle_secondary_adapter(connection: Connection, enable: bool):
    secondary_ifc = None
    try:
        secondary_ifc = await set_secondary_ifc_state(connection, enable)
        yield
    finally:
        await set_secondary_ifc_state(connection, not enable, secondary_ifc)
