import platform
import random
from abc import ABC, abstractmethod
from enum import Enum, auto
from tests.utils.logger import log
from tests.utils.process import Process
from typing import List, Set


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
    DOCKER_OPENWRT_CLIENT_1 = auto()
    DOCKER_INTERNAL_SYMMETRIC_CLIENT = auto()
    VM_WINDOWS_1 = auto()
    VM_WINDOWS_2 = auto()
    VM_MAC = auto()
    DOCKER_CONE_GW_1 = auto()
    DOCKER_CONE_GW_2 = auto()
    DOCKER_CONE_GW_3 = auto()
    VM_LINUX_FULLCONE_GW_1 = auto()
    VM_LINUX_FULLCONE_GW_2 = auto()
    DOCKER_SYMMETRIC_GW_1 = auto()
    DOCKER_SYMMETRIC_GW_2 = auto()
    DOCKER_UDP_BLOCK_GW_1 = auto()
    DOCKER_UDP_BLOCK_GW_2 = auto()
    DOCKER_UPNP_GW_1 = auto()
    DOCKER_UPNP_GW_2 = auto()
    DOCKER_OPENWRT_GW_1 = auto()
    VM_OPENWRT_GW_1 = auto()
    DOCKER_VPN_1 = auto()
    DOCKER_VPN_2 = auto()
    VM_LINUX_NLX_1 = auto()
    DOCKER_INTERNAL_SYMMETRIC_GW = auto()
    DOCKER_DERP_1 = auto()
    DOCKER_DERP_2 = auto()
    DOCKER_DERP_3 = auto()
    DOCKER_DNS_SERVER_1 = auto()
    DOCKER_DNS_SERVER_2 = auto()
    DOCKER_PHOTO_ALBUM = auto()
    DOCKER_WINDOWS_GW_1 = auto()
    DOCKER_WINDOWS_GW_2 = auto()
    DOCKER_WINDOWS_GW_3 = auto()
    DOCKER_WINDOWS_GW_4 = auto()
    DOCKER_WINDOWS_VM_1 = auto()
    DOCKER_WINDOWS_VM_2 = auto()
    DOCKER_MAC_GW_1 = auto()
    DOCKER_MAC_GW_2 = auto()
    DOCKER_CORE_API_1 = auto()
    DOCKER_MQTT_BROKER_1 = auto()
    DOCKER_STUN_1 = auto()
    DOCKER_UDP_SERVER = auto()

    def __repr__(self):
        return f"{self.name}"


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
    _target_os: TargetOS
    _tag: ConnectionTag

    def __init__(self, target_os: TargetOS, tag: ConnectionTag) -> None:
        self._target_os = target_os
        self._tag = tag

    @abstractmethod
    def create_process(
        self, command: List[str], kill_id=None, term_type=None, quiet=False
    ) -> "Process":
        pass

    @property
    def target_os(self) -> TargetOS:
        return self._target_os

    @target_os.setter
    def target_os(self, target_os: TargetOS) -> None:
        assert self.target_os
        self._target_os = target_os

    @property
    def tag(self) -> ConnectionTag:
        return self._tag

    @tag.setter
    def tag(self, tag: ConnectionTag) -> None:
        assert tag
        self._tag = tag

    @abstractmethod
    async def download(self, remote_path: str, local_path: str) -> None:
        pass

    @abstractmethod
    async def upload_file(self, local_file_path: str, remote_file_path: str) -> None:
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
        log.debug("[%s]: %s", connection.tag, output)

    start_port = random.randint(15000, 55000)
    num_ports = random.randint(2000, 5000)

    if connection.tag in [ConnectionTag.VM_WINDOWS_1, ConnectionTag.VM_WINDOWS_2]:
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
    elif connection.tag is ConnectionTag.VM_MAC:
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

    await connection.create_process(cmd, quiet=True).execute(on_output, on_output)
    EPHEMERAL_SETUP_SET.add(connection.tag)
