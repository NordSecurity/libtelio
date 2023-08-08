from .router import Router
from config import (
    LINUX_VM_PRIMARY_GATEWAY,
    DERP_PRIMARY,
    DERP_SECONDARY,
    VPN_SERVER_SUBNET,
)
from contextlib import asynccontextmanager
from typing import AsyncIterator
from utils.connection import Connection


class MacRouter(Router):
    _connection: Connection
    _interface_name: str

    def __init__(self, connection: Connection):
        self._connection = connection
        self._interface_name = "utun10"

    def get_interface_name(self) -> str:
        return self._interface_name

    async def setup_interface(self, address: str) -> None:
        await self._connection.create_process(
            ["ifconfig", self._interface_name, "add", address, "255.192.0.0", address]
        ).execute()

    async def create_meshnet_route(self) -> None:
        await self._connection.create_process(
            ["route", "add", "100.64.0.0/10", "-interface", self._interface_name]
        ).execute()

        await self._connection.create_process(
            [
                "route",
                "add",
                str(DERP_PRIMARY.get("ipv4")) + "/32",
                LINUX_VM_PRIMARY_GATEWAY,
            ]
        ).execute()

        await self._connection.create_process(
            [
                "route",
                "add",
                str(DERP_SECONDARY.get("ipv4")) + "/32",
                LINUX_VM_PRIMARY_GATEWAY,
            ]
        ).execute()

    async def create_vpn_route(self) -> None:
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
