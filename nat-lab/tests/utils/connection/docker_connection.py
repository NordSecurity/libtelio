from aiodocker.containers import DockerContainer
from utils.connection import Connection, TargetOS
from utils.process import Process, DockerProcess
from typing import List


class DockerConnection(Connection):
    _container: DockerContainer

    def __init__(self, container: DockerContainer):
        self._container = container
        self.target_os = TargetOS.Linux

    def create_process(
        self,
        command: List[str],
    ) -> "Process":
        return DockerProcess(self._container, command)
