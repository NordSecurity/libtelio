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
    name: str
    enabled: bool
    ipv4: Optional[str] = None

    def __repr__(self):
        return (
            f"Interface(name={self.name!r}, enabled={self.enabled}, ipv4={self.ipv4!r})"
        )

    @staticmethod
    async def get_network_interfaces(connection: Connection) -> List["Interface"]:
        def find_interface(
            interfaces: list[Interface], name: str
        ) -> Optional[Interface]:
            return next((iface for iface in interfaces if iface.name == name), None)

        interfaces: List[Interface] = []

        # Look for existing enabled/disabled interfaces
        process = await connection.create_process(
            ["netsh", "interface", "show", "interface"], quiet=True
        ).execute()

        stdout = process.get_stdout()
        log.debug("[%s]: %s", connection.tag, stdout)

        matches = re.finditer(
            r"^(.+[a][b][l][e][d])[\s]+[\w]+[\s]+[\w]+[\s]+(.*$)",
            stdout,
            re.MULTILINE,
        )
        for match in matches:
            name = match.group(2).strip()
            if match.group(1).strip() == "Enabled":
                enabled = True
            elif match.group(1).strip() == "Disabled":
                enabled = False
            else:
                raise ValueError("Unknown Windows NIC state")

            interfaces.append(Interface(name, enabled))

        # Find their addresses for enabled interfaces (except loopback)
        process = await connection.create_process(
            ["netsh", "interface", "ipv4", "show", "addresses"],
            quiet=True,
        ).execute()

        stdout = process.get_stdout()
        log.debug("[%s]: %s", connection.tag, stdout)

        matches = re.finditer(
            r'Configuration for interface "([^"]+)"\s+(.*?)InterfaceMetric',
            stdout,
            re.DOTALL,
        )
        for match in matches:
            name = match.group(1)
            if name.startswith("Loopback"):
                continue

            ipv4_match = re.search(
                r"IP Address:\s+(\d+\.\d+\.\d+\.\d+)", match.group(2)
            )
            ipv4_address = ipv4_match.group(1).strip() if ipv4_match else ""

            interface = find_interface(interfaces, name)
            if interface:
                if not interface.enabled:
                    raise ValueError("Disabled interface with assigned address?")
                interface.ipv4 = ipv4_address
            else:
                interfaces.append(Interface(name, enabled=True, ipv4=ipv4_address))
                log.debug("Added interface: %s, %s", name, ipv4_address)

        return interfaces

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

    async def disable(self, connection: Connection) -> None:
        log.debug("[%s] Disabling interface: %s", connection.tag, self.name)
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

        self.enabled = False

    async def enable(self, connection: Connection) -> None:
        log.debug("[%s] Enabling interface: %s", connection.tag, self.name)
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
            if self.name == iface.name and iface.ipv4
        ]):
            await asyncio.sleep(0.5)


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

        def find_interface(prefix: str) -> Optional[Interface]:
            for interface in interfaces:
                if interface.enabled:
                    if interface.ipv4:
                        if interface.ipv4.startswith(prefix):
                            return interface
                    else:
                        raise ValueError("Interface enabled but IPv4 is unassigned")
            return None

        # Allow management interface to be shut down
        management_itf = find_interface((config.LIBVIRT_MANAGEMENT_NETWORK_PREFIX))
        primary_itf = find_interface(config.PRIMARY_VM_NETWORK_PREFIX)
        secondary_itf = find_interface(config.SECONDARY_VM_NETWORK_PREFIX)
        assert primary_itf, LookupError(
            "Couldn't find primary VM interface (10.55/16), is it enabled?"
        )
        assert secondary_itf, LookupError(
            "Couldn't find secondary VM interface (10.66/16), is it enabled?"
        )

        return NetworkSwitcherWindows(
            connection,
            management_itf,
            primary_itf,
            secondary_itf,
        )

    async def switch_to_primary_network(self) -> None:
        """Set default route via Linux VM @ $LINUX_VM_PRIMARY_GATEWAY"""

        await self._delete_existing_routes()
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

        await self._delete_existing_routes()
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

    async def _delete_existing_routes(self) -> None:
        # Deleting routes by interface name instead of network destination (0.0.0.0/0) makes
        # it possible to have multiple default routes at the same time: first default route
        # for LAN network, and second default route for VPN network.
        if self._mgmt_interface:
            await self._mgmt_interface.disable(self._connection)
        await self._primary_interface.delete_route(self._connection)
        await self._secondary_interface.delete_route(self._connection)
