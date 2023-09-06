import config
import re
from .network_switcher import NetworkSwitcher
from dataclasses import dataclass
from typing import List, Optional
from utils.connection import Connection
from utils.process import ProcessExecError


@dataclass
class Interface:
    def __init__(self, name: str, ipv4: str) -> None:
        self.name = name
        self.ipv4 = ipv4


class ConfiguredInterfaces:
    def __init__(self, default: str, primary: str, secondary: str) -> None:
        self.default = default
        self.primary = primary
        self.secondary = secondary

    @staticmethod
    async def find(connection: Connection) -> "ConfiguredInterfaces":
        interfaces = await ConfiguredInterfaces.get_network_interfaces(connection)

        def find_interface(prefix: str) -> str:
            for interface in interfaces:
                if interface.ipv4.startswith(prefix):
                    return interface.name
            assert False, f"interface not found with prefix `{prefix}`, {interfaces}"

        return ConfiguredInterfaces(
            find_interface(config.LIBVIRT_MANAGEMENT_NETWORK_PREFIX),
            find_interface(config.PRIMARY_VM_NETWORK_PREFIX),
            find_interface(config.SECONDARY_VM_NETWORK_PREFIX),
        )

    @staticmethod
    async def get_network_interfaces(connection: Connection) -> List[Interface]:
        process = await connection.create_process(
            ["netsh", "interface", "ipv4", "show", "addresses"]
        ).execute()

        matches = re.findall(
            r"Configuration for interface \"(.*)\"[\s\S]*?IP Address:\s*([\d.]*)",
            process.get_stdout(),
        )

        result: List[Interface] = []
        for match in matches:
            result.append(Interface(match[0], match[1]))

        return result


class NetworkSwitcherWindows(NetworkSwitcher):
    def __init__(self, connection: Connection) -> None:
        self._connection = connection
        self._interfaces: Optional[ConfiguredInterfaces] = None

    async def get_interfaces(self) -> ConfiguredInterfaces:
        if not self._interfaces:
            self._interfaces = await ConfiguredInterfaces.find(self._connection)
        return self._interfaces

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
                (await self.get_interfaces()).primary,
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
                (await self.get_interfaces()).secondary,
                f"nexthop={config.LINUX_VM_SECONDARY_GATEWAY}",
            ]
        ).execute()

    async def _delete_existing_route(self) -> None:
        # Deleting routes by interface name instead of network destination (0.0.0.0/0) makes
        # it possible to have multiple default routes at the same time: first default route
        # for LAN network, and second default route for VPN network.

        interfaces = await self.get_interfaces()
        await self._delete_route(interfaces.default)
        await self._delete_route(interfaces.primary)
        await self._delete_route(interfaces.secondary)

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
