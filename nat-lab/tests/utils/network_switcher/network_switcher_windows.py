import asyncio
import config
import re
from .network_switcher import NetworkSwitcher
from dataclasses import dataclass
from typing import List, Optional
from utils.command_grepper import CommandGrepper
from utils.connection import Connection
from utils.logger import log
from utils.process import ProcessExecError

STATUS_CHECK_TIMEOUT_S: float = 20.0


@dataclass
class Interface:
    def __init__(self, name: str, ipv4: str, enabled: bool = True) -> None:
        self.name = name
        self.ipv4 = ipv4
        self.enabled = enabled

    @staticmethod
    async def get_network_interfaces(connection: Connection) -> List["Interface"]:
        process = await connection.create_process(
            ["netsh", "interface", "ipv4", "show", "addresses"],
            quiet=True,  # ["netsh", "interface", "show", "interface"], quiet=True
        ).execute()

        stdout = process.get_stdout()
        log.debug(stdout)

        # matches = re.finditer(
        #     r"^([^\s]+).*(Ethernet.*$)",
        #     stdout,
        #     re.DOTALL,
        # )

        # result: List[Interface] = []
        # for match in matches:
        #     enabled = True if match.group(1) == "Enabled" else False
        #     name = match.group(2)

        #     result.append(Interface(name, enabled))

        # return result

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

    async def delete_route(self, connection: Connection) -> None:
        try:
            await connection.create_process(
                [
                    "netsh",
                    "interface",
                    "ipv4",
                    "delete",
                    "route",
                    "0.0.0.0/0",
                    self.name,
                ],
                quiet=True,
            ).execute()
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
            connection,
            [
                "netsh",
                "interface",
                "ipv4",
                "show",
                "route",
            ],
            timeout=STATUS_CHECK_TIMEOUT_S,
        ).check_not_exists(
            "0.0.0.0/0",
            [
                self.name,
            ],
        ):
            raise Exception("Failed to delete " + self.name + " route")

    async def disable_interface(self, connection: Connection) -> None:
        await connection.create_process(
            [
                "netsh",
                "interface",
                "set",
                "interface",
                self.name,
                "disable",
            ],
            quiet=True,
        ).execute()

        if not await CommandGrepper(
            connection,
            [
                "netsh",
                "interface",
                "ipv4",
                "show",
                "addresses",
                self.name,
            ],
            timeout=STATUS_CHECK_TIMEOUT_S,
        ).check_not_exists(self.name, None):
            raise Exception("Failed to disable management interface")

    async def enable_interface(self, connection: Connection) -> None:
        await connection.create_process(
            [
                "netsh",
                "interface",
                "set",
                "interface",
                self.name,
                "enable",
            ],
            quiet=True,
        ).execute()

        # wait for interface to appear in the list
        while not bool([
            iface
            for iface in await Interface.get_network_interfaces(connection)
            if self.name == iface.name
        ]):
            await asyncio.sleep(0.1)

        # wait for interface's ip to be assigned
        while bool([
            iface
            for iface in await Interface.get_network_interfaces(connection)
            if Interface(self.name, "").ipv4 == iface.ipv4
        ]):
            await asyncio.sleep(0.1)


class NetworkSwitcherWindows(NetworkSwitcher):
    def __init__(
        self,
        connection: Connection,
        mgmt_ifc: Optional[Interface],
        primary_ifc: Interface,
        secondary_ifc: Interface,
    ) -> None:
        self._connection = connection
        self._mgmt_interface = mgmt_ifc
        self._primary_interface = primary_ifc
        self._secondary_interface = secondary_ifc

    @staticmethod
    async def create(connection: Connection) -> "NetworkSwitcherWindows":
        interfaces = await Interface.get_network_interfaces(connection)

        for interface in interfaces:
            if not interface.enabled:
                pass

        def find_interface(prefix: str) -> Optional[Interface]:
            for interface in interfaces:
                if interface is not None:
                    if interface.ipv4.startswith(prefix):
                        return interface
            return None

        # Allow management interface to be shut down
        management_itf = find_interface((config.LIBVIRT_MANAGEMENT_NETWORK_PREFIX))
        primary_itf = find_interface(config.PRIMARY_VM_NETWORK_PREFIX)
        secondary_itf = find_interface(config.SECONDARY_VM_NETWORK_PREFIX)
        assert primary_itf is not None
        assert secondary_itf is not None

        return NetworkSwitcherWindows(
            connection,
            management_itf,
            primary_itf,
            secondary_itf,
        )

    async def switch_to_primary_network(self) -> None:
        """Set default route via Linux VM @ $LINUX_VM_PRIMARY_GATEWAY"""

        await self._delete_existing_route()
        await self._connection.create_process([
            "netsh",
            "interface",
            "ipv4",
            "add",
            "route",
            "0.0.0.0/0",
            self._primary_interface.name,
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
            timeout=STATUS_CHECK_TIMEOUT_S,
        ).check_exists(
            "0.0.0.0/0",
            [
                config.LINUX_VM_PRIMARY_GATEWAY,
            ],
        ):
            raise Exception("Failed to switch to primary network")

    async def switch_to_secondary_network(self) -> None:
        """Set default route via Linux VM @ $LINUX_VM_SECONDARY_GATEWAY"""

        await self._delete_existing_route()
        await self._connection.create_process([
            "netsh",
            "interface",
            "ipv4",
            "add",
            "route",
            "0.0.0.0/0",
            self._secondary_interface.name,
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
            timeout=STATUS_CHECK_TIMEOUT_S,
        ).check_exists(
            "0.0.0.0/0",
            [
                config.LINUX_VM_SECONDARY_GATEWAY,
            ],
        ):
            raise Exception("Failed to switch to secondary network")

    async def _delete_existing_route(self) -> None:
        # Deleting routes by interface name instead of network destination (0.0.0.0/0) makes
        # it possible to have multiple default routes at the same time: first default route
        # for LAN network, and second default route for VPN network.
        if self._mgmt_interface:
            await self._mgmt_interface.disable_interface(self._connection)
        await self._primary_interface.delete_route(self._connection)
        await self._secondary_interface.delete_route(self._connection)
