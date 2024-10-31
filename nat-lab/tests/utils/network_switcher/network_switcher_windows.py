import asyncio
import config
import re
from .network_switcher import NetworkSwitcher
from contextlib import asynccontextmanager
from dataclasses import dataclass
from typing import AsyncIterator, List, Optional
from utils.command_grepper import CommandGrepper
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

        matches = re.finditer(
            r'Configuration for interface "([^"]+)"\s+(.*?)InterfaceMetric',
            stdout,
            re.DOTALL,
        )

        result: List[Interface] = []
        for match in matches:
            name = match.group(1)
            ip_address_match = re.search(
                r"IP Address:\s+(\d+\.\d+\.\d+\.\d+)", match.group(2)
            )
            ip_address = ip_address_match.group(1) if ip_address_match else ""
            result.append(Interface(name, ip_address))

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
    _status_check_timeout: float = 20.0

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
        """Set default route via Linux VM @ $LINUX_VM_PRIMARY_GATEWAY"""

        await self._delete_existing_route()
        await self._connection.create_process([
            "netsh",
            "interface",
            "ipv4",
            "add",
            "route",
            "0.0.0.0/0",
            self._interfaces.primary,
            f"nexthop={config.LINUX_VM_PRIMARY_GATEWAY}",
        ]).execute()

        if not await CommandGrepper(
            self._connection,
            [
                "netsh",
                "interface",
                "ipv4",
                "show",
                "route",
            ],
            timeout=self._status_check_timeout,
        ).check_exists(
            "0.0.0.0/0",
            [
                config.LINUX_VM_PRIMARY_GATEWAY,
            ],
        ):
            raise Exception("Failed to switch to primary network")

        try:
            yield
        finally:
            # Restoring management interface after a test
            # Seems to be causing some flakyness. In order to
            # Test this theory, restoring is being disabled
            #
            # await self._enable_management_interface()
            pass

    @asynccontextmanager
    async def switch_to_secondary_network(self) -> AsyncIterator:
        """Set default route via Linux VM @ $LINUX_VM_SECONDARY_GATEWAY"""

        await self._delete_existing_route()
        await self._connection.create_process([
            "netsh",
            "interface",
            "ipv4",
            "add",
            "route",
            "0.0.0.0/0",
            self._interfaces.secondary,
            f"nexthop={config.LINUX_VM_SECONDARY_GATEWAY}",
        ]).execute()

        if not await CommandGrepper(
            self._connection,
            [
                "netsh",
                "interface",
                "ipv4",
                "show",
                "route",
            ],
            timeout=self._status_check_timeout,
        ).check_exists(
            "0.0.0.0/0",
            [
                config.LINUX_VM_SECONDARY_GATEWAY,
            ],
        ):
            raise Exception("Failed to switch to secondary network")

        try:
            yield
        finally:
            # Restoring management interface after a test
            # Seems to be causing some flakyness. In order to
            # Test this theory, restoring is being disabled
            #
            # await self._enable_management_interface()
            pass

    async def _delete_existing_route(self) -> None:
        # Deleting routes by interface name instead of network destination (0.0.0.0/0) makes
        # it possible to have multiple default routes at the same time: first default route
        # for LAN network, and second default route for VPN network.

        await self._disable_management_interface()
        await self._delete_route(self._interfaces.primary)
        await self._delete_route(self._interfaces.secondary)

    async def _delete_route(self, interface_name: str) -> None:
        try:
            await self._connection.create_process([
                "netsh",
                "interface",
                "ipv4",
                "delete",
                "route",
                "0.0.0.0/0",
                interface_name,
            ]).execute()
        except ProcessExecError as exception:
            if (
                "The filename, directory name, or volume label syntax is incorrect"
                in exception.stdout
            ):
                return
            if "Element not found" in exception.stdout:
                return
            raise exception

        if not await CommandGrepper(
            self._connection,
            [
                "netsh",
                "interface",
                "ipv4",
                "show",
                "route",
            ],
            timeout=self._status_check_timeout,
        ).check_not_exists(
            "0.0.0.0/0",
            [
                interface_name,
            ],
        ):
            raise Exception("Failed to delete " + interface_name + " route")

    async def _disable_management_interface(self) -> None:
        if self._interfaces.default is not None:
            await self._connection.create_process([
                "netsh",
                "interface",
                "set",
                "interface",
                self._interfaces.default,
                "disable",
            ]).execute()

            if not await CommandGrepper(
                self._connection,
                [
                    "netsh",
                    "interface",
                    "ipv4",
                    "show",
                    "addresses",
                    self._interfaces.default,
                ],
                timeout=self._status_check_timeout,
            ).check_not_exists(self._interfaces.default, None):
                raise Exception("Failed to disable management interface")

    async def _enable_management_interface(self) -> None:
        if self._interfaces.default is not None:
            await self._connection.create_process([
                "netsh",
                "interface",
                "set",
                "interface",
                self._interfaces.default,
                "enable",
            ]).execute()

            # wait for interface to appear in the list
            while not bool([
                iface
                for iface in await Interface.get_network_interfaces(self._connection)
                if self._interfaces.default == iface.name
            ]):
                await asyncio.sleep(0.1)

            # wait for interface's ip to be assigned
            while bool([
                iface
                for iface in await Interface.get_network_interfaces(self._connection)
                if Interface(self._interfaces.default, "").ipv4 == iface.ipv4
            ]):
                await asyncio.sleep(0.1)
