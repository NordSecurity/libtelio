from .network_switcher import NetworkSwitcher
from utils.connection import Connection


class NetworkSwitcherDocker(NetworkSwitcher):
    def __init__(self, connection: Connection) -> None:
        self._connection = connection

    async def switch_to_primary_network(self) -> None:
        await self._connection.create_process(
            ["/libtelio/nat-lab/bin/configure_route.sh", "primary"]
        ).execute()

    async def switch_to_secondary_network(self) -> None:
        await self._connection.create_process(
            ["/libtelio/nat-lab/bin/configure_route.sh", "secondary"]
        ).execute()
