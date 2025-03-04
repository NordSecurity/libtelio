from .connection import Connection, TargetOS, ConnectionTag, setup_ephemeral_ports
from aiodocker import Docker
from aiodocker.containers import DockerContainer
from asyncio import to_thread
from config import LINUX_INTERFACE_NAME
from contextlib import asynccontextmanager
from datetime import datetime
from subprocess import run, DEVNULL
from typing import List, Type, Dict, AsyncIterator
from typing_extensions import Self
from utils.process import Process, DockerProcess

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
    ConnectionTag.DOCKER_DERP_1: "derp-01",
    ConnectionTag.DOCKER_DERP_2: "derp-02",
    ConnectionTag.DOCKER_DERP_3: "derp-03",
    ConnectionTag.DOCKER_DNS_SERVER_1: "dns-server-1",
    ConnectionTag.DOCKER_DNS_SERVER_2: "dns-server-2",
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
    ConnectionTag.VM_WINDOWS_1: ConnectionTag.DOCKER_CONE_GW_3,
    ConnectionTag.VM_WINDOWS_2: ConnectionTag.DOCKER_CONE_GW_3,
    ConnectionTag.VM_MAC: ConnectionTag.DOCKER_CONE_GW_3,
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


class DockerConnection(Connection):
    _container: DockerContainer

    def __init__(self, container: DockerContainer, tag: ConnectionTag):
        super().__init__(TargetOS.Linux, tag)
        self._container = container

    async def __aenter__(self):
        await self.restore_ip_tables()
        await self.clean_interface()
        await setup_ephemeral_ports(self)
        return self

    async def __aexit__(self, *exc_details):
        await self.restore_ip_tables()
        await self.clean_interface()
        return self

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
                ["docker", "cp", container_id(self.tag) + ":" + remote_path, local_path],
                stdout=DEVNULL,
                stderr=DEVNULL,
            )

        await to_thread(aux)

    def create_process(
        self, command: List[str], kill_id=None, term_type=None
    ) -> "Process":
        process = DockerProcess(
            self._container, container_id(self.tag), command, kill_id
        )
        print(
            datetime.now(),
            "Executing",
            command,
            "on",
            self.tag.name,
        )
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
        await self.create_process(["conntrack", "-F"]).execute()
        await self.create_process(["iptables-restore", "iptables_backup"]).execute()
        await self.create_process(["ip6tables-restore", "ip6tables_backup"]).execute()

    async def clean_interface(self) -> None:
        try:
            await self.create_process(
                ["ip", "link", "delete", LINUX_INTERFACE_NAME]
            ).execute()
        except:
            pass  # Most of the time there will be no interface to be deleted


def container_id(tag: ConnectionTag) -> str:
    if tag in DOCKER_SERVICE_IDS:
        return f"nat-lab-{DOCKER_SERVICE_IDS[tag]}-1"
    assert False, f"tag {tag} not a docker container"
