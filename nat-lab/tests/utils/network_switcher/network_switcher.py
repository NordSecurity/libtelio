from abc import ABC, abstractmethod


class NetworkSwitcher(ABC):
    def __init__(self) -> None:
        pass

    @abstractmethod
    async def switch_to_primary_network(self) -> None:
        pass

    @abstractmethod
    async def switch_to_secondary_network(self) -> None:
        pass
