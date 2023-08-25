from .router import Router, IPStack, IPProto
from config import LINUX_VM_PRIMARY_GATEWAY, DERP_SERVERS, VPN_SERVER_SUBNET
from contextlib import asynccontextmanager
from typing import AsyncIterator, List
from utils.connection import Connection


class MacRouter(Router):
    _connection: Connection
    _interface_name: str

    def __init__(self, connection: Connection):
        super().__init__()
        self._connection = connection
        self._interface_name = "utun10"

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
            ).execute()

            for derp in DERP_SERVERS:
                await self._connection.create_process(
                    [
                        "route",
                        "add",
                        str(derp.get("ipv4")) + "/32",
                        LINUX_VM_PRIMARY_GATEWAY,
                    ],
                ).execute()

        if self.ip_stack in [IPStack.IPv6, IPStack.IPv4v6]:
            await self._connection.create_process(
                [
                    "route",
                    "add",
                    "-inet6",
                    "fc74:656c:696f::/64",
                    "-interface",
                    self._interface_name,
                ],
            ).execute()

    async def create_vpn_route(self) -> None:
        if self.ip_stack == IPStack.IPv6:
            assert False, "IPv6 for VPN is not supported"

        await self._connection.create_process(["route", "delete", "default"]).execute()

        await self._connection.create_process(
            ["route", "add", "default", "-interface", self._interface_name]
        ).execute()

        await self._connection.create_process(
            ["route", "add", VPN_SERVER_SUBNET, LINUX_VM_PRIMARY_GATEWAY]
        ).execute()

    async def delete_interface(self) -> None:
        pass

    async def delete_vpn_route(self) -> None:
        if self.ip_stack == IPStack.IPv6:
            assert False, "IPv6 for VPN is not supported"

        await self._connection.create_process(["route", "delete", "default"]).execute()

        await self._connection.create_process(
            ["route", "add", "default", LINUX_VM_PRIMARY_GATEWAY]
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
