from abc import ABC, abstractmethod
from contextlib import asynccontextmanager
from typing import AsyncIterator


class NetworkSwitcher(ABC):
    def __init__(self) -> None:
        pass

    @abstractmethod
    @asynccontextmanager
    async def switch_to_primary_network(self) -> AsyncIterator:
        yield

    @abstractmethod
    @asynccontextmanager
    async def switch_to_secondary_network(self) -> AsyncIterator:
        yield
