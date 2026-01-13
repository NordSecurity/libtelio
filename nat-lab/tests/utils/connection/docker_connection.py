from .connection import Connection, TargetOS, ConnectionTag, setup_ephemeral_ports
from aiodocker import Docker
from aiodocker.containers import DockerContainer
from asyncio import to_thread
from contextlib import asynccontextmanager
from logging import DEBUG, INFO
from subprocess import run, DEVNULL
from tests.config import LINUX_INTERFACE_NAME
from tests.utils.logger import log
from tests.utils.process import Process, DockerProcess, ProcessExecError
from typing import List, Type, Dict, AsyncIterator
from typing_extensions import Self

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
    ConnectionTag.DOCKER_OPENWRT_CLIENT_1: "openwrt-client-01",
    ConnectionTag.DOCKER_INTERNAL_SYMMETRIC_CLIENT: "internal-symmetric-client-01",
    ConnectionTag.DOCKER_CONE_GW_1: "cone-gw-01",
    ConnectionTag.DOCKER_CONE_GW_2: "cone-gw-02",
    ConnectionTag.DOCKER_CONE_GW_3: "cone-gw-03",
    ConnectionTag.DOCKER_SYMMETRIC_GW_1: "symmetric-gw-01",
    ConnectionTag.DOCKER_SYMMETRIC_GW_2: "symmetric-gw-02",
    ConnectionTag.DOCKER_UDP_BLOCK_GW_1: "udp-block-gw-01",
    ConnectionTag.DOCKER_UDP_BLOCK_GW_2: "udp-block-gw-02",
    ConnectionTag.DOCKER_UPNP_GW_1: "upnp-gw-01",
    ConnectionTag.DOCKER_UPNP_GW_2: "upnp-gw-02",
    ConnectionTag.DOCKER_OPENWRT_GW_1: "openwrt-gw-01",
    ConnectionTag.DOCKER_VPN_1: "vpn-01",
    ConnectionTag.DOCKER_VPN_2: "vpn-02",
    ConnectionTag.DOCKER_INTERNAL_SYMMETRIC_GW: "internal-symmetric-gw-01",
    ConnectionTag.DOCKER_DERP_1: "derp-01",
    ConnectionTag.DOCKER_DERP_2: "derp-02",
    ConnectionTag.DOCKER_DERP_3: "derp-03",
    ConnectionTag.DOCKER_DNS_SERVER_1: "dns-server-1",
    ConnectionTag.DOCKER_DNS_SERVER_2: "dns-server-2",
    ConnectionTag.DOCKER_PHOTO_ALBUM: "photo-album",
    ConnectionTag.DOCKER_WINDOWS_GW_1: "windows-gw-01",
    ConnectionTag.DOCKER_WINDOWS_GW_2: "windows-gw-02",
    ConnectionTag.DOCKER_WINDOWS_GW_3: "windows-gw-03",
    ConnectionTag.DOCKER_WINDOWS_GW_4: "windows-gw-04",
    ConnectionTag.DOCKER_WINDOWS_VM_1: "windows-client-01",
    ConnectionTag.DOCKER_WINDOWS_VM_2: "windows-client-02",
    ConnectionTag.DOCKER_MAC_GW_1: "mac-gw-01",
    ConnectionTag.DOCKER_MAC_GW_2: "mac-gw-02",
    ConnectionTag.DOCKER_CORE_API_1: "core-api",
    ConnectionTag.DOCKER_MQTT_BROKER_1: "mqtt-broker",
    ConnectionTag.DOCKER_STUN_1: "stun-01",
    ConnectionTag.DOCKER_UDP_SERVER: "udp-server",
}

DOCKER_GW_MAP: Dict[ConnectionTag, ConnectionTag] = {
    ConnectionTag.DOCKER_CONE_CLIENT_1: ConnectionTag.DOCKER_CONE_GW_1,
    ConnectionTag.DOCKER_CONE_CLIENT_2: ConnectionTag.DOCKER_CONE_GW_2,
    ConnectionTag.DOCKER_FULLCONE_CLIENT_1: ConnectionTag.VM_LINUX_FULLCONE_GW_1,
    ConnectionTag.DOCKER_FULLCONE_CLIENT_2: ConnectionTag.VM_LINUX_FULLCONE_GW_2,
    ConnectionTag.DOCKER_SYMMETRIC_CLIENT_1: ConnectionTag.DOCKER_SYMMETRIC_GW_1,
    ConnectionTag.DOCKER_SYMMETRIC_CLIENT_2: ConnectionTag.DOCKER_SYMMETRIC_GW_2,
    ConnectionTag.DOCKER_UPNP_CLIENT_1: ConnectionTag.DOCKER_UPNP_GW_1,
    ConnectionTag.DOCKER_UPNP_CLIENT_2: ConnectionTag.DOCKER_UPNP_GW_2,
    ConnectionTag.DOCKER_SHARED_CLIENT_1: ConnectionTag.DOCKER_CONE_GW_1,
    ConnectionTag.DOCKER_UDP_BLOCK_CLIENT_1: ConnectionTag.DOCKER_UDP_BLOCK_GW_1,
    ConnectionTag.DOCKER_UDP_BLOCK_CLIENT_2: ConnectionTag.DOCKER_UDP_BLOCK_GW_2,
    ConnectionTag.VM_WINDOWS_1: ConnectionTag.DOCKER_WINDOWS_GW_1,
    ConnectionTag.VM_WINDOWS_2: ConnectionTag.DOCKER_WINDOWS_GW_3,
    ConnectionTag.VM_MAC: ConnectionTag.DOCKER_MAC_GW_1,
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

DOCKER_VM_MAP: Dict[ConnectionTag, ConnectionTag] = {
    ConnectionTag.VM_WINDOWS_1: ConnectionTag.DOCKER_WINDOWS_VM_1,
    ConnectionTag.VM_WINDOWS_2: ConnectionTag.DOCKER_WINDOWS_VM_2,
}

DOCKER_SERVICE_SKIP_IPTABLES: list[ConnectionTag] = [
    ConnectionTag.DOCKER_UDP_SERVER,
    ConnectionTag.DOCKER_CORE_API_1,
    ConnectionTag.DOCKER_MQTT_BROKER_1,
    ConnectionTag.DOCKER_STUN_1,
]


class DockerConnection(Connection):
    _container: DockerContainer

    def __init__(self, container: DockerContainer, tag: ConnectionTag):
        super().__init__(TargetOS.Linux, tag)
        self._container = container

    async def __aenter__(self):
        if self.tag not in DOCKER_SERVICE_SKIP_IPTABLES:
            try:
                await self.restore_ip_tables()
            except ProcessExecError as e:
                log.warning(e)
        await self.clean_interface()
        await setup_ephemeral_ports(self)
        return self

    async def __aexit__(self, *_):
        if self.tag not in DOCKER_SERVICE_SKIP_IPTABLES:
            try:
                await self.restore_ip_tables()
            except ProcessExecError as e:
                log.warning(e)
        await self.clean_interface()

    @classmethod
    @asynccontextmanager
    async def new_connection(
        cls: Type[Self], docker: Docker, tag: ConnectionTag
    ) -> AsyncIterator["DockerConnection"]:
        async with cls(
            await docker.containers.get(container_id(tag)), tag
        ) as connection:
            yield connection

    async def download(self, remote_path: str, local_path: str) -> None:
        def aux():
            run(
                [
                    "docker",
                    "cp",
                    container_id(self.tag) + ":" + remote_path,
                    local_path,
                ],
                stdout=DEVNULL,
                stderr=DEVNULL,
            )

        await to_thread(aux)

    async def upload_file(self, local_file_path: str, remote_file_path: str) -> None:
        raise NotImplementedError(
            "File upload is not implemented for Docker connection"
        )

    def create_process(
        self, command: List[str], kill_id=None, term_type=None, quiet=False
    ) -> "Process":
        process = DockerProcess(
            self._container, container_id(self.tag), command, kill_id
        )

        if not quiet:
            log_level = INFO
        else:
            log_level = DEBUG
        log.log(log_level, "[%s] Executing %s", self.tag.name, " ".join(command))

        return process

    async def get_ip_address(self) -> tuple[str, str]:
        details = await self._container.show()
        networks = details["NetworkSettings"]["Networks"]
        if not networks.values():
            raise Exception(
                "Docker container '" + self._container["Name"] + "' has no ip addresses"
            )
        networks = list(networks.values())
        ip_address = networks[0]["IPAMConfig"]["IPv4Address"]
        return ("localhost", ip_address)

    async def mapped_ports(self) -> tuple[str, str]:
        details = await self._container.show()
        ports = details["NetworkSettings"]["Ports"]
        if not ports.items():
            return ("0", "0")
        mapped_port = list(ports.items())[0]
        container_port = mapped_port[0].split("/")[0]
        host_port = mapped_port[1][0]["HostPort"]
        return (str(host_port), str(container_port))

    async def restore_ip_tables(self) -> None:
        await self.create_process(["conntrack", "-F"], quiet=True).execute()
        await self.create_process(
            ["iptables-restore", "iptables_backup"], quiet=True
        ).execute()
        await self.create_process(
            ["ip6tables-restore", "ip6tables_backup"], quiet=True
        ).execute()

    async def clean_interface(self) -> None:
        try:
            await self.create_process(
                ["ip", "link", "delete", LINUX_INTERFACE_NAME], quiet=True
            ).execute()
        except:
            pass  # Most of the time there will be no interface to be deleted


def container_id(tag: ConnectionTag) -> str:
    if tag in DOCKER_SERVICE_IDS:
        return f"nat-lab-{DOCKER_SERVICE_IDS[tag]}-1"
    assert False, f"tag {tag} not a docker container"


async def is_running(tag: ConnectionTag) -> bool:
    cid = container_id(tag)
    async with Docker() as docker:
        clist = await docker.containers.list()
        for c in clist:
            name = (await c.show())["Name"]
            if name == f"/{cid}":
                return True
    return False
