from .network_switcher import NetworkSwitcher
from tests.utils.connection import Connection


class NetworkSwitcherOpenwrt(NetworkSwitcher):
    def __init__(self, connection: Connection) -> None:
        self._connection = connection

    async def switch_to_primary_network(self):
        pass

    async def switch_to_secondary_network(self):
        pass
