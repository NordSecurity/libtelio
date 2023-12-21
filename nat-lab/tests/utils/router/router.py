from abc import ABC, abstractmethod
from contextlib import asynccontextmanager
from enum import Enum, auto
from ipaddress import ip_address, IPv4Address
from typing import AsyncIterator, List, Optional

# fmt: off
REG_IPV4SEG  = r'(?:25[0-5]|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9])'
REG_IPV4ADDR = r'(?:(?:' + REG_IPV4SEG + r'\.){3,3}' + REG_IPV4SEG + r')'
REG_IPV6SEG  = r'(?:(?:[0-9a-fA-F]){1,4})'
REG_IPV6GROUPS = (
    r'(?:' + REG_IPV6SEG + r':){7,7}' + REG_IPV6SEG,                  # 1:2:3:4:5:6:7:8
    r'(?:' + REG_IPV6SEG + r':){1,7}:',                           # 1::, 1:2:3:4:5:6:7::
    r'(?:' + REG_IPV6SEG + r':){1,6}:' + REG_IPV6SEG,                 # 1::8, 1:2:3:4:5:6::8, 1:2:3:4:5:6::8
    r'(?:' + REG_IPV6SEG + r':){1,5}(?::' + REG_IPV6SEG + r'){1,2}',  # 1::7:8, 1:2:3:4:5::7:8, :2:3:4:5::8
    r'(?:' + REG_IPV6SEG + r':){1,4}(?::' + REG_IPV6SEG + r'){1,3}',  # 1::6:7:8, 1:2:3:4::6:7:8, 1:2:3:4::8
    r'(?:' + REG_IPV6SEG + r':){1,3}(?::' + REG_IPV6SEG + r'){1,4}',  # 1::5:6:7:8, 1:2:3::5:6:7:8, 1:2:3::8
    r'(?:' + REG_IPV6SEG + r':){1,2}(?::' + REG_IPV6SEG + r'){1,5}',  # 1::4:5:6:7:8, 1:2::4:5:6:7:8, 1:2::8
    REG_IPV6SEG + r':(?:(?::' + REG_IPV6SEG + r'){1,6})',             # 1::3:4:5:6:7:8, 1::3:4:5:6:7:8, 1::8
    r':(?:(?::' + REG_IPV6SEG + r'){1,7}|:)',                     # ::2:3:4:5:6:7:8, ::2:3:4:5:6:7:8, ::8, ::
    r'fe80:(?::' + REG_IPV6SEG + r'){0,4}%[0-9a-zA-Z]{1,}',       # fe80::7:8%eth0, fe80::7:8%1 (link-local IPv6 addresses with zone index)
    r'::(?:ffff(?::0{1,4}){0,1}:){0,1}[^\s:]' + REG_IPV4ADDR,     # ::255.255.255.255, ::ffff:255.255.255.255, ::ffff:0:255.255.255.255 (IPv4-mapped IPv6 addresses and IPv4-translated addresses)
    r'(?:' + REG_IPV6SEG + r':){1,6}:?[^\s:]' + REG_IPV4ADDR          # 2001:db8:3:4::192.0.2.33, 64:ff9b::192.0.2.33 (IPv4-Embedded IPv6 Address)
)
REG_IPV6ADDR = '|'.join(['(?:{})'.format(g) for g in REG_IPV6GROUPS[::-1]])  # pylint: disable=consider-using-f-string
# fmt: on


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
