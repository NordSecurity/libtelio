from aiodocker import Docker
from utils.connection import Connection, TargetOS
from contextlib import asynccontextmanager
from enum import Enum, auto
from typing import AsyncIterator, Dict, Tuple, Optional
from utils import container_util, windows_vm_util, mac_vm_util
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
    ConnectionTag.DOCKER_UPNP_GW_1: "upnp-gw-01",
    ConnectionTag.DOCKER_UPNP_GW_2: "upnp-gw-02",
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
            container_id = f"nat-lab-{DOCKER_SERVICE_IDS[tag]}-1"
            yield await container_util.get(docker, container_id)

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
async def new_connection_with_network_switcher(
    tag: ConnectionTag,
) -> AsyncIterator[Tuple[Connection, Optional[NetworkSwitcher]]]:
    async with new_connection_raw(tag) as connection:
        network_switcher = create_network_switcher(tag, connection)
        if network_switcher:
            await network_switcher.switch_to_primary_network()

        yield (connection, network_switcher)


@asynccontextmanager
async def new_connection_by_tag(tag: ConnectionTag) -> AsyncIterator[Connection]:
    async with new_connection_with_network_switcher(tag) as (
        connection,
        network_switcher,
    ):
        yield connection


def container_id(tag: ConnectionTag) -> str:
    if tag in DOCKER_SERVICE_IDS:
        return f"nat-lab-{DOCKER_SERVICE_IDS[tag]}-1"
    else:
        assert False, f"tag {tag} not a docker container"
