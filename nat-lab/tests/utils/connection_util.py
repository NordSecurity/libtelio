from aiodocker import Docker
from utils.connection import Connection, TargetOS
from contextlib import asynccontextmanager
from enum import Enum, auto
from typing import AsyncIterator, Dict, Tuple, Optional, List
from utils import container_util, windows_vm_util, mac_vm_util
from utils.connection_tracker import ConnectionTracker, ConnectionTrackerConfig
import config

from utils.network_switcher import (
    NetworkSwitcher,
    NetworkSwitcherDocker,
    NetworkSwitcherWindows,
    NetworkSwitcherMac,
)


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
    DOCKER_UDP_BLOCK_CLIENT_1 = auto()
    DOCKER_UDP_BLOCK_CLIENT_2 = auto()
    WINDOWS_VM = auto()
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
    ConnectionTag.DOCKER_UDP_BLOCK_CLIENT_1: "udp-block-client-01",
    ConnectionTag.DOCKER_UDP_BLOCK_CLIENT_2: "udp-block-client-02",
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
}


DOCKER_GW_MAP: Dict[ConnectionTag, ConnectionTag] = {
    ConnectionTag.DOCKER_CONE_CLIENT_1: ConnectionTag.DOCKER_CONE_GW_1,
    ConnectionTag.DOCKER_CONE_CLIENT_2: ConnectionTag.DOCKER_CONE_GW_1,
    ConnectionTag.DOCKER_FULLCONE_CLIENT_1: ConnectionTag.DOCKER_FULLCONE_GW_1,
    ConnectionTag.DOCKER_FULLCONE_CLIENT_2: ConnectionTag.DOCKER_FULLCONE_GW_2,
    ConnectionTag.DOCKER_SYMMETRIC_CLIENT_1: ConnectionTag.DOCKER_SYMMETRIC_GW_1,
    ConnectionTag.DOCKER_SYMMETRIC_CLIENT_2: ConnectionTag.DOCKER_SYMMETRIC_GW_2,
    ConnectionTag.DOCKER_UPNP_CLIENT_1: ConnectionTag.DOCKER_UPNP_GW_1,
    ConnectionTag.DOCKER_UPNP_CLIENT_2: ConnectionTag.DOCKER_UPNP_GW_2,
    ConnectionTag.DOCKER_SHARED_CLIENT_1: ConnectionTag.DOCKER_CONE_GW_1,
    ConnectionTag.DOCKER_UDP_BLOCK_CLIENT_1: ConnectionTag.DOCKER_UDP_BLOCK_GW_1,
    ConnectionTag.DOCKER_UDP_BLOCK_CLIENT_2: ConnectionTag.DOCKER_UDP_BLOCK_GW_2,
    ConnectionTag.WINDOWS_VM: ConnectionTag.DOCKER_CONE_GW_3,
    ConnectionTag.MAC_VM: ConnectionTag.DOCKER_CONE_GW_3,
}


def get_libtelio_binary_path(path: str, connection: Connection) -> str:
    target_os = connection.target_os
    if target_os == TargetOS.Linux:
        return config.LIBTELIO_BINARY_PATH_DOCKER + path
    elif target_os == TargetOS.Windows or target_os == TargetOS.Mac:
        return config.LIBTELIO_BINARY_PATH_VM + path
    else:
        assert False, f"target_os not supported '{target_os}'"


@asynccontextmanager
async def new_connection_raw(tag: ConnectionTag) -> AsyncIterator[Connection]:
    if tag in DOCKER_SERVICE_IDS:
        async with Docker() as docker:
            async with container_util.get(docker, container_id(tag)) as connection:
                yield connection

    elif tag == ConnectionTag.WINDOWS_VM:
        async with windows_vm_util.new_connection() as connection:
            yield connection

    elif tag == ConnectionTag.MAC_VM:
        async with mac_vm_util.new_connection() as connection:
            yield connection

    else:
        assert False, f"tag {tag} not supported"


def create_network_switcher(
    tag: ConnectionTag, connection: Connection
) -> Optional[NetworkSwitcher]:
    if tag in DOCKER_SERVICE_IDS:
        return NetworkSwitcherDocker(connection)

    elif tag == ConnectionTag.WINDOWS_VM:
        return NetworkSwitcherWindows(connection)

    elif tag == ConnectionTag.MAC_VM:
        return NetworkSwitcherMac(connection)

    else:
        return None


@asynccontextmanager
async def new_connection_manager_by_tag(
    tag: ConnectionTag,
    conn_tracker_config: Optional[List[ConnectionTrackerConfig]] = None,
) -> AsyncIterator[
    Tuple[
        Connection, Optional[Connection], Optional[NetworkSwitcher], ConnectionTracker
    ]
]:
    async with new_connection_raw(tag) as connection:
        network_switcher = create_network_switcher(tag, connection)
        if network_switcher:
            await network_switcher.switch_to_primary_network()
        if tag in DOCKER_GW_MAP:
            async with new_connection_raw(DOCKER_GW_MAP[tag]) as gw_connection:
                async with ConnectionTracker(
                    connection
                    if tag not in [ConnectionTag.WINDOWS_VM, ConnectionTag.MAC_VM]
                    else gw_connection,
                    conn_tracker_config,
                ) as conn_tracker:
                    yield (connection, gw_connection, network_switcher, conn_tracker)
        else:
            async with ConnectionTracker(
                connection,
                conn_tracker_config,
            ) as conn_tracker:
                yield (connection, None, network_switcher, conn_tracker)


@asynccontextmanager
async def new_connection_with_network_switcher(
    tag: ConnectionTag,
) -> AsyncIterator[Tuple[Connection, Optional[NetworkSwitcher]]]:
    async with new_connection_manager_by_tag(tag) as (
        connection,
        _,
        network_switcher,
        _,
    ):
        yield (connection, network_switcher)


@asynccontextmanager
async def new_connection_with_conn_tracker(
    tag: ConnectionTag, conn_tracker_config: Optional[List[ConnectionTrackerConfig]]
) -> AsyncIterator[Tuple[Connection, ConnectionTracker]]:
    async with new_connection_manager_by_tag(tag, conn_tracker_config) as (
        connection,
        _,
        _,
        conn_tracker,
    ):
        yield (connection, conn_tracker)


@asynccontextmanager
async def new_connection_by_tag(tag: ConnectionTag) -> AsyncIterator[Connection]:
    async with new_connection_manager_by_tag(tag) as (
        connection,
        _,
        _,
        _,
    ):
        yield connection


def container_id(tag: ConnectionTag) -> str:
    if tag in DOCKER_SERVICE_IDS:
        return f"nat-lab-{DOCKER_SERVICE_IDS[tag]}-1"
    else:
        assert False, f"tag {tag} not a docker container"
