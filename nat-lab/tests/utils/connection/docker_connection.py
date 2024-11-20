from .connection import Connection, TargetOS
from aiodocker import Docker
from aiodocker.containers import DockerContainer
from asyncio import to_thread
from config import LINUX_INTERFACE_NAME
from datetime import datetime
from subprocess import run
from typing import List, Type
from typing_extensions import Self
from utils.process import Process, DockerProcess


class DockerConnection(Connection):
    _container: DockerContainer
    _name: str

    def __init__(self, container: DockerContainer, container_name: str):
        super().__init__(TargetOS.Linux)
        self._name = container_name
        self._container = container

    @classmethod
    async def new(cls: Type[Self], docker: Docker, container_name: str) -> Self:
        new_docker_conn = cls(
            await docker.containers.get(container_name), container_name
        )
        await new_docker_conn.restore_ip_tables()
        await new_docker_conn.clean_interface()

        return new_docker_conn

    def container_name(self) -> str:
        return self._name

    def target_name(self) -> str:
        return self.container_name()

    async def download(self, remote_path: str, local_path: str) -> None:
        def aux():
            run(["docker", "cp", self._name + ":" + remote_path, local_path])

        await to_thread(aux)

    def create_process(self, command: List[str], kill_id=None) -> "Process":
        process = DockerProcess(self._container, command, kill_id)
        print(
            datetime.now(),
            "Executing",
            command,
            "on",
            self._name,
            "with Kill ID:",
            process.get_kill_id(),
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
