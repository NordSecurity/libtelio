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

    def __init__(self, container: DockerContainer, container_name: str):
        super().__init__(TargetOS.Linux)
        self._name = container_name
        self._container = container

    def create_process(self, command: List[str]) -> "Process":
        print(datetime.now(), "Executing", command, "on", self._name)
        return DockerProcess(self._container, command)
