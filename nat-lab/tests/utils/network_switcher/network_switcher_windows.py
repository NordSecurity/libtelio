import config
import re
from .network_switcher import NetworkSwitcher
from contextlib import asynccontextmanager
from dataclasses import dataclass
from typing import AsyncIterator, List, Optional
from utils.connection import Connection
from utils.process import ProcessExecError


@dataclass
class Interface:
    def __init__(self, name: str, ipv4: str) -> None:
        self.name = name
        self.ipv4 = ipv4

    @staticmethod
    async def get_network_interfaces(connection: Connection) -> List["Interface"]:
        process = await connection.create_process(
            ["netsh", "interface", "ipv4", "show", "addresses"]
        ).execute()

        stdout = process.get_stdout()
        print(stdout)

        matches = re.findall(
            r"Configuration for interface \"(.*)\"[\s\S]*?IP Address:\s*([\d.]*)",
            stdout,
        )

        result: List[Interface] = []
        for match in matches:
            print(match)
            result.append(Interface(match[0], match[1]))

        return result


class ConfiguredInterfaces:
    def __init__(self, default: Optional[str], primary: str, secondary: str) -> None:
        self.default = default
        self.primary = primary
        self.secondary = secondary

    @staticmethod
    async def create(connection: Connection) -> "ConfiguredInterfaces":
        interfaces = await Interface.get_network_interfaces(connection)

        def find_interface(prefix: str) -> Optional[str]:
            for interface in interfaces:
                if interface.ipv4.startswith(prefix):
                    return interface.name
            return None

        # Allow management interface to be shut down
        management_itf = find_interface((config.LIBVIRT_MANAGEMENT_NETWORK_PREFIX))
        primary_itf = find_interface(config.PRIMARY_VM_NETWORK_PREFIX)
        secondary_itf = find_interface(config.SECONDARY_VM_NETWORK_PREFIX)
        assert primary_itf is not None
        assert secondary_itf is not None

        return ConfiguredInterfaces(management_itf, primary_itf, secondary_itf)


class NetworkSwitcherWindows(NetworkSwitcher):
    def __init__(
        self, connection: Connection, interfaces: ConfiguredInterfaces
    ) -> None:
        self._connection = connection
        self._interfaces = interfaces

    @staticmethod
    async def create(connection: Connection) -> "NetworkSwitcherWindows":
        return NetworkSwitcherWindows(
            connection, await ConfiguredInterfaces.create(connection)
        )

    @asynccontextmanager
    async def switch_to_primary_network(self) -> AsyncIterator:
        await self._delete_existing_route()
        await self._connection.create_process(
            [
                "netsh",
                "interface",
                "ipv4",
                "add",
                "route",
                "0.0.0.0/0",
                self._interfaces.primary,
                f"nexthop={config.LINUX_VM_PRIMARY_GATEWAY}",
            ]
        ).execute()
        try:
            yield
        finally:
            await self._enable_management_interface()

    @asynccontextmanager
    async def switch_to_secondary_network(self) -> AsyncIterator:
        await self._delete_existing_route()
        await self._connection.create_process(
            [
                "netsh",
                "interface",
                "ipv4",
                "add",
                "route",
                "0.0.0.0/0",
                self._interfaces.secondary,
                f"nexthop={config.LINUX_VM_SECONDARY_GATEWAY}",
            ]
        ).execute()
        try:
            yield
        finally:
            await self._enable_management_interface()

    async def _delete_existing_route(self) -> None:
        # Deleting routes by interface name instead of network destination (0.0.0.0/0) makes
        # it possible to have multiple default routes at the same time: first default route
        # for LAN network, and second default route for VPN network.

        await self._disable_management_interface()
        await self._delete_route(self._interfaces.primary)
        await self._delete_route(self._interfaces.secondary)

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

    async def _disable_management_interface(self) -> None:
        if self._interfaces.default is not None:
            await self._connection.create_process(
                [
                    "netsh",
                    "interface",
                    "set",
                    "interface",
                    self._interfaces.default,
                    "disable",
                ]
            ).execute()

    async def _enable_management_interface(self) -> None:
        if self._interfaces.default is not None:
            await self._connection.create_process(
                [
                    "netsh",
                    "interface",
                    "set",
                    "interface",
                    self._interfaces.default,
                    "enable",
                ]
            ).execute()
