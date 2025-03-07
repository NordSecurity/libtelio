import platform
import random
from abc import ABC, abstractmethod
from datetime import datetime
from enum import Enum, auto
from typing import List, Optional, Set
from utils.process import Process


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
    DOCKER_DERP_1 = auto()
    DOCKER_DERP_2 = auto()
    DOCKER_DERP_3 = auto()
    DOCKER_DNS_SERVER_1 = auto()
    DOCKER_DNS_SERVER_2 = auto()


EPHEMERAL_SETUP_SET: Set[ConnectionTag] = set()


class TargetOS(Enum):
    Linux = auto()
    Windows = auto()
    Mac = auto()

    @staticmethod
    def local():
        system = platform.system()
        if system == "Windows":
            return TargetOS.Windows
        if system == "Linux":
            return TargetOS.Linux
        if system == "Darwin":
            return TargetOS.Mac
        raise ValueError(f"{system} is not supported")


class Connection(ABC):
    _target_os: Optional[TargetOS]

    def __init__(self, target_os: TargetOS) -> None:
        self._target_os = target_os

    @abstractmethod
    def create_process(
        self, command: List[str], kill_id=None, term_type=None
    ) -> "Process":
        pass

    @property
    def target_os(self) -> TargetOS:
        assert self._target_os
        return self._target_os

    @target_os.setter
    def target_os(self, target_os: TargetOS) -> None:
        self._target_os = target_os

    @abstractmethod
    def target_name(self) -> str:
        pass

    @abstractmethod
    async def download(self, remote_path: str, local_path: str) -> None:
        pass

    async def get_ip_address(self) -> tuple[str, str]:
        ip = "127.0.0.1"
        return (ip, ip)

    async def mapped_ports(self) -> tuple[str, str]:
        return ("0", "0")

    async def restore_ip_tables(self) -> None:
        pass

    async def clean_interface(self) -> None:
        pass


async def clear_ephemeral_setups_set():
    EPHEMERAL_SETUP_SET.clear()


async def setup_ephemeral_ports(connection: Connection):
    if connection.tag in EPHEMERAL_SETUP_SET:
        return

    async def on_output(output: str) -> None:
        print(datetime.now(), f"[{connection.tag.name}]: {output}")

    start_port = random.randint(5000, 55000)
    num_ports = random.randint(2000, 5000)

    if connection.tag in [ConnectionTag.WINDOWS_VM_1, ConnectionTag.WINDOWS_VM_2]:
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
    elif connection.tag is ConnectionTag.MAC_VM:
        cmd = [
            "sysctl",
            "-w",
            f"net.inet.ip.portrange.first={start_port}",
            f"net.inet.ip.portrange.last={start_port + num_ports}",
        ]
    elif (
        connection.tag.name.lower().startswith("docker")
        and "client" in connection.tag.name.lower()
    ):
        cmd = [
            "sysctl",
            "-w",
            f"net.ipv4.ip_local_port_range={start_port} {start_port + num_ports}",
        ]
    else:
        return

    await connection.create_process(cmd).execute(on_output, on_output)
    EPHEMERAL_SETUP_SET.add(connection.tag)
