from .connection import Connection, TargetOS
from aiodocker.containers import DockerContainer
from datetime import datetime
from typing import List
from utils.process import Process, DockerProcess


class DockerConnection(Connection):
    _container: DockerContainer
    _name: str

    def container_name(self) -> str:
        return self._name

    def target_name(self) -> str:
        return self.container_name()

    def __init__(self, container: DockerContainer, container_name: str):
        super().__init__(TargetOS.Linux)
        self._name = container_name
        self._container = container

    def create_process(self, command: List[str]) -> "Process":
        print(datetime.now(), "Executing", command, "on", self._name)
        return DockerProcess(self._container, command)

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
            raise Exception(
                "Docker container '" + self._container["Name"] + "' has no mapped ports"
            )
        mapped_port = list(ports.items())[0]
        container_port = mapped_port[0].split("/")[0]
        host_port = mapped_port[1][0]["HostPort"]
        return (str(host_port), str(container_port))
