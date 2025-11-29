from .network_switcher import NetworkSwitcher
from tests.config import GW_ADDR_MAP
from tests.utils.connection import Connection


class NetworkSwitcherLinux(NetworkSwitcher):
    def __init__(self, connection: Connection) -> None:
        self._connection = connection

    async def switch_to_primary_network(self) -> None:
        if GW_ADDR_MAP[self._connection.tag]["primary"] == "":
            return

        await self._connection.create_process(
            ["ip", "route", "delete", "10.0.0.0/16"]
        ).execute()
        await self._connection.create_process([
            "ip",
            "route",
            "add",
            "10.0.0.0/16",
            "via",
            GW_ADDR_MAP[self._connection.tag]["primary"],
            "enp0s3",
        ]).execute()

    async def switch_to_secondary_network(self) -> None:
        if GW_ADDR_MAP[self._connection.tag]["secondary"] == "":
            return

        await self._connection.create_process(
            ["ip", "route", "delete", "10.0.0.0/16"]
        ).execute()
        await self._connection.create_process([
            "ip",
            "route",
            "add",
            "10.0.0.0/16",
            "via",
            GW_ADDR_MAP[self._connection.tag]["secondary"],
            "enp0s4",
        ]).execute()
