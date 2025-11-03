from abc import ABC, abstractmethod
from enum import Enum


class InterfaceState(Enum):
    Disabled = 0
    Enabled = 1
    Unknown = 2


class NetworkSwitcher(ABC):
    def __init__(self) -> None:
        pass

    @abstractmethod
    async def switch_to_primary_network(self) -> None:
        pass

    @abstractmethod
    async def switch_to_secondary_network(self) -> None:
        pass
