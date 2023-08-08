from .connection import Connection, TargetOS
from aiodocker.containers import DockerContainer
from typing import List
from utils.process import Process, DockerProcess


class DockerConnection(Connection):
    _container: DockerContainer

    def __init__(self, container: DockerContainer):
        super().__init__(TargetOS.Linux)
        self._container = container

    def create_process(self, command: List[str]) -> "Process":
        return DockerProcess(self._container, command)
