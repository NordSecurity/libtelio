from abc import ABC, abstractmethod
from contextlib import asynccontextmanager
from typing import AsyncIterator


class Router(ABC):
    @abstractmethod
    def get_interface_name(self) -> str:
        pass

    @abstractmethod
    async def setup_interface(self, address: str) -> None:
        pass

    @abstractmethod
    async def create_meshnet_route(self) -> None:
        pass

    @abstractmethod
    async def create_vpn_route(self) -> None:
        pass

    @abstractmethod
    async def delete_interface(self) -> None:
        pass

    @abstractmethod
    async def delete_vpn_route(self) -> None:
        pass

    @abstractmethod
    async def create_exit_node_route(self) -> None:
        pass

    @abstractmethod
    async def delete_exit_node_route(self) -> None:
        pass

    @abstractmethod
    @asynccontextmanager
    async def disable_path(self, address: str) -> AsyncIterator:
        yield

    @abstractmethod
    @asynccontextmanager
    async def break_tcp_conn_to_host(self, address: str) -> AsyncIterator:
        yield
