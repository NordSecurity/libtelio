from abc import ABC, abstractmethod
from contextlib import asynccontextmanager
from enum import Enum, auto
from ipaddress import ip_address, IPv4Address
from typing import AsyncIterator, List, Optional


class IPStack(Enum):
    IPv4 = auto()
    IPv6 = auto()
    IPv4v6 = auto()


class IPProto(Enum):
    IPv4 = auto()
    IPv6 = auto()


def get_ip_address_type(address: str) -> Optional[IPProto]:
    try:
        return (
            IPProto.IPv4
            if isinstance(ip_address(address), IPv4Address)
            else IPProto.IPv6
        )
    except ValueError:
        return None


class Router(ABC):
    _ip_stack: IPStack

    def __init__(self, ip_stack: IPStack) -> None:
        self._ip_stack = ip_stack

    def check_ip_address(self, address: str) -> Optional[IPProto]:
        addr_proto = get_ip_address_type(address)

        if (
            addr_proto is None
            or (self.ip_stack == IPStack.IPv4 and addr_proto == IPProto.IPv6)
            or (self.ip_stack == IPStack.IPv6 and addr_proto == IPProto.IPv4)
        ):
            return None

        return addr_proto

    @abstractmethod
    def get_interface_name(self) -> str:
        pass

    @abstractmethod
    async def setup_interface(self, addresses: List[str]) -> None:
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

    @abstractmethod
    @asynccontextmanager
    async def break_udp_conn_to_host(self, address: str) -> AsyncIterator:
        yield

    @abstractmethod
    @asynccontextmanager
    async def reset_upnpd(self) -> AsyncIterator:
        yield

    @property
    def ip_stack(self) -> IPStack:
        return self._ip_stack

    @ip_stack.setter
    def ip_stack(self, ip_stack: IPStack) -> None:
        self._ip_stack = ip_stack
