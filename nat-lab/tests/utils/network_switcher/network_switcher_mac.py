import config
from .network_switcher import NetworkSwitcher
from utils.connection import Connection


class NetworkSwitcherMac(NetworkSwitcher):
    def __init__(self, connection: Connection) -> None:
        self._connection = connection

    async def switch_to_primary_network(self) -> None:
        await self._delete_existing_route()

        await self._connection.create_process(
            ["route", "add", "default", config.LINUX_VM_PRIMARY_GATEWAY]
        ).execute()

    async def switch_to_secondary_network(self) -> None:
        await self._delete_existing_route()

        await self._connection.create_process(
            ["route", "add", "default", config.LINUX_VM_SECONDARY_GATEWAY]
        ).execute()

    async def _delete_existing_route(self) -> None:
        await self._connection.create_process(["route", "delete", "default"]).execute()
