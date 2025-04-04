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
    def __init__(self, primary: str, secondary: str) -> None:
        self.primary = primary
        self.secondary = secondary

    @staticmethod
    async def create(connection: Connection) -> "ConfiguredInterfaces":
        interfaces = await Interface.get_network_interfaces(connection)

        def find_interface(ip: str) -> Optional[str]:
            for interface in interfaces:
                if interface.ipv4 == ip:
                    return interface.name
            return None

        # Allow management interface to be shut down
        primary_itf = find_interface(config.LAN_ADDR_MAP[connection.tag]["primary"])
        secondary_itf = find_interface(config.LAN_ADDR_MAP[connection.tag]["secondary"])
        assert primary_itf is not None
        assert secondary_itf is not None

        return ConfiguredInterfaces(primary_itf, secondary_itf)


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
        await self._delete_existing_route()
        await self._connection.create_process([
            "netsh",
            "interface",
            "ipv4",
            "add",
            "route",
            "0.0.0.0/0",
            self._interfaces.primary,
            f"nexthop={config.GW_ADDR_MAP[self._connection.tag]['primary']}",
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
                config.GW_ADDR_MAP[self._connection.tag]["primary"],
            ],
        ):
            raise Exception("Failed to switch to primary network")

        yield

    @asynccontextmanager
    async def switch_to_secondary_network(self) -> AsyncIterator:
        await self._delete_existing_route()

        await self._connection.create_process([
            "netsh",
            "interface",
            "ipv4",
            "add",
            "route",
            "0.0.0.0/0",
            self._interfaces.secondary,
            f"nexthop={config.GW_ADDR_MAP[self._connection.tag]['secondary']}",
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
                config.GW_ADDR_MAP[self._connection.tag]["secondary"],
            ],
        ):
            raise Exception("Failed to switch to secondary network")

        yield

    async def _delete_existing_route(self) -> None:
        # Deleting routes by interface name instead of network destination (0.0.0.0/0) makes
        # it possible to have multiple default routes at the same time: first default route
        # for LAN network, and second default route for VPN network.
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
