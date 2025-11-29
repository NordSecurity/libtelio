from .router import Router, IPStack, IPProto
from contextlib import asynccontextmanager
from tests.config import LIBTELIO_IPV6_WG_SUBNET
from tests.utils.connection import Connection
from typing import AsyncIterator, List


class MacRouter(Router):
    _connection: Connection
    _interface_name: str

    def __init__(self, connection: Connection, ip_stack: IPStack):
        super().__init__(ip_stack)
        self._connection = connection
        self._interface_name = "utun10"
        self._meshnet_route_v4_created = False
        self._meshnet_route_v6_created = False

    def get_interface_name(self) -> str:
        return self._interface_name

    async def setup_interface(self, addresses: List[str]) -> None:
        for address in addresses:
            addr_proto = self.check_ip_address(address)

            if addr_proto == IPProto.IPv4:
                await self._connection.create_process(
                    [
                        "ifconfig",
                        self._interface_name,
                        "inet",
                        "add",
                        address,
                        "255.192.0.0",
                        address,
                    ],
                    quiet=True,
                ).execute()
            elif addr_proto == IPProto.IPv6:
                await self._connection.create_process(
                    [
                        "ifconfig",
                        self._interface_name,
                        "inet6",
                        "add",
                        address,
                        "prefixlen",
                        "64",
                    ],
                    quiet=True,
                ).execute()

    async def deconfigure_interface(self, addresses: List[str]) -> None:
        if self._meshnet_route_v4_created is True:
            await self._connection.create_process(
                [
                    "route",
                    "delete",
                    "-inet",
                    "100.64.0.0/10",
                    "-interface",
                    self._interface_name,
                ],
                quiet=False,
            ).execute()
            self._meshnet_route_v4_created = True
        if self._meshnet_route_v6_created is True:
            await self._connection.create_process(
                [
                    "route",
                    "delete",
                    "-inet6",
                    LIBTELIO_IPV6_WG_SUBNET + "::/64",
                    "-interface",
                    self._interface_name,
                ],
                quiet=True,
            ).execute()
            self._meshnet_route_v6_created = False

        for address in addresses:
            addr_proto = self.check_ip_address(address)

            if addr_proto == IPProto.IPv4:
                await self._connection.create_process(
                    [
                        "ifconfig",
                        self._interface_name,
                        "inet",
                        "delete",
                        address,
                        "255.192.0.0",
                        address,
                    ],
                    quiet=True,
                ).execute()
            elif addr_proto == IPProto.IPv6:
                await self._connection.create_process(
                    [
                        "ifconfig",
                        self._interface_name,
                        "inet6",
                        "delete",
                        address,
                        "prefixlen",
                        "64",
                    ],
                    quiet=True,
                ).execute()

    async def enable_interface(self) -> None:
        await self._connection.create_process(
            ["ifconfig", self._interface_name, "up"],
            quiet=True,
        ).execute()

    async def disable_interface(self) -> None:
        await self._connection.create_process(
            ["ifconfig", self._interface_name, "down"],
            quiet=True,
        ).execute()

    async def create_meshnet_route(self) -> None:
        if self.ip_stack in [IPStack.IPv4, IPStack.IPv4v6]:
            await self._connection.create_process(
                [
                    "route",
                    "add",
                    "-inet",
                    "100.64.0.0/10",
                    "-interface",
                    self._interface_name,
                ],
                quiet=True,
            ).execute()
            self._meshnet_route_v4_created = True

        if self.ip_stack in [IPStack.IPv6, IPStack.IPv4v6]:
            await self._connection.create_process(
                [
                    "route",
                    "add",
                    "-inet6",
                    LIBTELIO_IPV6_WG_SUBNET + "::/64",
                    "-interface",
                    self._interface_name,
                ],
                quiet=True,
            ).execute()
            self._meshnet_route_v6_created = True

    async def create_fake_ipv4_route(self, route: str) -> None:
        pass

    async def create_vpn_route(self) -> None:
        if self.ip_stack in [IPStack.IPv4, IPStack.IPv4v6]:
            await self._connection.create_process([
                "route",
                "add",
                "-inet",
                "0/1",
                "-interface",
                self._interface_name,
            ]).execute()
            await self._connection.create_process([
                "route",
                "add",
                "-inet",
                "128/1",
                "-interface",
                self._interface_name,
            ]).execute()

        if self.ip_stack in [IPStack.IPv6, IPStack.IPv4v6]:
            await self._connection.create_process([
                "route",
                "add",
                "-inet6",
                "default",
                "-interface",
                self._interface_name,
            ]).execute()

    async def delete_interface(self, name=None) -> None:
        pass

    async def delete_vpn_route(self) -> None:
        if self.ip_stack in [IPStack.IPv4, IPStack.IPv4v6]:
            await self._connection.create_process(
                ["route", "delete", "-inet", "0/1"],
                quiet=True,
            ).execute()

            await self._connection.create_process(
                ["route", "delete", "-inet", "128/1"]
            ).execute()

        if self.ip_stack in [IPStack.IPv6, IPStack.IPv4v6]:
            await self._connection.create_process(
                ["route", "delete", "-inet6", "default"],
                quiet=True,
            ).execute()

    async def create_exit_node_route(self) -> None:
        pass

    async def delete_exit_node_route(self) -> None:
        pass

    @asynccontextmanager
    async def disable_path(
        self, address: str  # pylint: disable=unused-argument
    ) -> AsyncIterator:
        yield

    @asynccontextmanager
    async def break_tcp_conn_to_host(
        self, address: str  # pylint: disable=unused-argument
    ) -> AsyncIterator:
        yield

    @asynccontextmanager
    async def break_udp_conn_to_host(
        self, address: str  # pylint: disable=unused-argument
    ) -> AsyncIterator:
        yield

    @asynccontextmanager
    async def block_udp_port(
        self, port: int  # pylint: disable=unused-argument
    ) -> AsyncIterator:
        yield

    @asynccontextmanager
    async def block_tcp_port(
        self, port: int  # pylint: disable=unused-argument
    ) -> AsyncIterator:
        yield

    @asynccontextmanager
    async def reset_upnpd(self) -> AsyncIterator:
        yield

    def set_interface_name(
        self, new_interface_name: str  # pylint: disable=unused-argument
    ) -> None:
        self._interface_name = new_interface_name
