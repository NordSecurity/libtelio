from utils.connection import Connection
from utils.process import ProcessExecError
from utils.network_switcher import NetworkSwitcher
import config

VAGRANT_DEFAULT_IF = "Ethernet"  # 10.0.2.0/24
PRIMARY_IF = "Ethernet 2"  # 10.55.0.11
SECONDARY_IF = "Ethernet 3"  # 10.66.0.11


class NetworkSwitcherWindows(NetworkSwitcher):
    def __init__(
        self,
        connection: Connection,
    ) -> None:
        self._connection = connection

    async def switch_to_primary_network(self) -> None:
        await self._delete_existing_route()

        await self._connection.create_process(
            [
                "netsh",
                "interface",
                "ipv4",
                "add",
                "route",
                "0.0.0.0/0",
                PRIMARY_IF,
                f"nexthop={config.LINUX_VM_PRIMARY_GATEWAY}",
            ]
        ).execute()

    async def switch_to_secondary_network(self) -> None:
        await self._delete_existing_route()

        await self._connection.create_process(
            [
                "netsh",
                "interface",
                "ipv4",
                "add",
                "route",
                "0.0.0.0/0",
                SECONDARY_IF,
                f"nexthop={config.LINUX_VM_SECONDARY_GATEWAY}",
            ]
        ).execute()

    async def _delete_existing_route(self) -> None:
        # Deleting routes by interface name instead of network destination (0.0.0.0/0) makes
        # it possible to have multiple default routes at the same time: first default route
        # for LAN network, and second default route for VPN network.

        await self._delete_route(VAGRANT_DEFAULT_IF)
        await self._delete_route(PRIMARY_IF)
        await self._delete_route(SECONDARY_IF)

    async def _delete_route(self, interface_name: str) -> None:
        try:
            await self._connection.create_process(
                [
                    "netsh",
                    "interface",
                    "ipv4",
                    "delete",
                    "route",
                    "0.0.0.0/0",
                    interface_name,
                ]
            ).execute()
        except ProcessExecError as exception:
            if (
                "The filename, directory name, or volume label syntax is incorrect"
                in exception.stdout
            ):
                pass
            elif "Element not found" in exception.stdout:
                pass
            else:
                raise exception
