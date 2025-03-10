import platform
from abc import ABC, abstractmethod
from enum import Enum, auto
from typing import List, Optional
from utils.process import Process


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
