import config
from .network_switcher import NetworkSwitcher
from config import (
    DERP_SERVERS,
    LINUX_VM_PRIMARY_GATEWAY,
    LINUX_VM_SECONDARY_GATEWAY,
    VPN_SERVER_SUBNET,
)
from contextlib import asynccontextmanager
from typing import AsyncIterator
from utils.connection import Connection


class NetworkSwitcherMac(NetworkSwitcher):
    def __init__(self, connection: Connection) -> None:
        self._connection = connection

    @asynccontextmanager
    async def switch_to_primary_network(self) -> AsyncIterator:
        """Set default route via Linux VM @ $LINUX_VM_PRIMARY_GATEWAY"""

        await self._delete_existing_route()
        await self._connection.create_process(
            ["route", "add", "default", LINUX_VM_PRIMARY_GATEWAY]
        ).execute()
        await self._connection.create_process(
            ["route", "add", "-inet", VPN_SERVER_SUBNET, LINUX_VM_PRIMARY_GATEWAY]
        ).execute()

        for derp in DERP_SERVERS:
            await self._connection.create_process(
                [
                    "route",
                    "add",
                    str(derp.ipv4) + "/32",
                    LINUX_VM_PRIMARY_GATEWAY,
                ],
            ).execute()
        yield

    @asynccontextmanager
    async def switch_to_secondary_network(self) -> AsyncIterator:
        """Set default route via Linux VM @ $LINUX_VM_SECONDARY_GATEWAY"""

        await self._delete_existing_route()
        await self._connection.create_process(
            ["route", "add", "default", LINUX_VM_SECONDARY_GATEWAY]
        ).execute()
        await self._connection.create_process(
            ["route", "add", "-inet", VPN_SERVER_SUBNET, LINUX_VM_SECONDARY_GATEWAY]
        ).execute()

        for derp in config.DERP_SERVERS:
            await self._connection.create_process(
                [
                    "route",
                    "add",
                    str(derp.ipv4) + "/32",
                    LINUX_VM_SECONDARY_GATEWAY,
                ],
            ).execute()
        yield

    async def _delete_existing_route(self) -> None:
        await self._connection.create_process(["route", "delete", "default"]).execute()
        await self._connection.create_process(
            ["route", "delete", "-inet", VPN_SERVER_SUBNET]
        ).execute()
        for derp in DERP_SERVERS:
            await self._connection.create_process(
                [
                    "route",
                    "delete",
                    str(derp.ipv4) + "/32",
                ],
            ).execute()
