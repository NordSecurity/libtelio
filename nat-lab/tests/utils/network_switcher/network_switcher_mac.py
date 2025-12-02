from .network_switcher import NetworkSwitcher
from tests import config
from tests.config import DERP_SERVERS, GW_ADDR_MAP, VPN_SERVER_SUBNET
from tests.utils.connection import Connection


class NetworkSwitcherMac(NetworkSwitcher):
    def __init__(self, connection: Connection) -> None:
        self._connection = connection

    async def switch_to_primary_network(self) -> None:
        await self._delete_existing_route()
        await self._connection.create_process(
            ["route", "add", "default", GW_ADDR_MAP[self._connection.tag]["primary"]]
        ).execute()
        await self._connection.create_process([
            "route",
            "add",
            "-inet",
            VPN_SERVER_SUBNET,
            GW_ADDR_MAP[self._connection.tag]["primary"],
        ]).execute()

        for derp in DERP_SERVERS:
            await self._connection.create_process(
                [
                    "route",
                    "add",
                    str(derp.ipv4) + "/32",
                    GW_ADDR_MAP[self._connection.tag]["primary"],
                ],
            ).execute()

    async def switch_to_secondary_network(self) -> None:
        await self._delete_existing_route()
        await self._connection.create_process(
            ["route", "add", "default", GW_ADDR_MAP[self._connection.tag]["secondary"]]
        ).execute()
        await self._connection.create_process([
            "route",
            "add",
            "-inet",
            VPN_SERVER_SUBNET,
            GW_ADDR_MAP[self._connection.tag]["secondary"],
        ]).execute()

        for derp in config.DERP_SERVERS:
            await self._connection.create_process(
                [
                    "route",
                    "add",
                    str(derp.ipv4) + "/32",
                    GW_ADDR_MAP[self._connection.tag]["secondary"],
                ],
            ).execute()

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
