from .network_switcher import NetworkSwitcher
from contextlib import asynccontextmanager
from typing import AsyncIterator
from utils.connection import Connection


class NetworkSwitcherDocker(NetworkSwitcher):
    def __init__(self, connection: Connection) -> None:
        self._connection = connection

    @asynccontextmanager
    async def switch_to_primary_network(self) -> AsyncIterator:
        """Add route to the "internet" (10.0.0.0/16) through $CLIENT_GATEWAY_PRIMARY"""
        await self._connection.create_process(
            ["/libtelio/nat-lab/bin/configure_route.sh", "primary"]
        ).execute()
        yield

    @asynccontextmanager
    async def switch_to_secondary_network(self) -> AsyncIterator:
        """Add route to the "internet" (10.0.0.0/16) through $CLIENT_GATEWAY_SECONDARY (Not available for common clients)"""
        await self._connection.create_process(
            ["/libtelio/nat-lab/bin/configure_route.sh", "secondary"]
        ).execute()
        yield
