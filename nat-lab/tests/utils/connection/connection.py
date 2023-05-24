from abc import ABC, abstractmethod
from utils.process import Process
from enum import Enum, auto
from typing import List, Optional


class TargetOS(Enum):
    Linux = auto()
    Windows = auto()
    Mac = auto()


class Connection(ABC):
    _target_os: Optional[TargetOS]

    def __init__(self) -> None:
        self._target_os = None

    @abstractmethod
    def create_process(
        self,
        command: List[str],
    ) -> "Process":
        pass

    @property
    def target_os(self) -> TargetOS:
        assert self._target_os
        return self._target_os

    @target_os.setter
    def target_os(self, target_os: TargetOS) -> None:
        self._target_os = target_os
