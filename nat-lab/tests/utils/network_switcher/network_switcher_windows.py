import asyncio
import re
from .network_switcher import NetworkSwitcher, InterfaceState
from dataclasses import dataclass
from tests import config
from tests.utils.command_grepper import CommandGrepper
from tests.utils.connection import Connection
from tests.utils.logger import log
from tests.utils.process import ProcessExecError
from typing import List, Optional

STATUS_CHECK_TIMEOUT_S: float = 120.0


@dataclass
class Interface:
    name: str
    ipv4: Optional[str] = None
    __state: InterfaceState = InterfaceState.Unknown

    @property
    def state(self) -> InterfaceState:
        return self.__state

    def __init__(
        self,
        name: str,
        state: Optional[InterfaceState] = None,
        ipv4: Optional[str] = None,
    ):
        self.name = name
        assert (
            state is not None and state is not InterfaceState.Unknown
        ), "Interface state init is only allowed if it's known"
        self.__state = state
        self.ipv4 = ipv4

    async def get_state(self, connection: Connection) -> InterfaceState:
        await self.update_state(connection)
        assert self.__state is not InterfaceState.Unknown
        return self.__state

    async def update_state(self, connection: Connection):
        updated_interfaces = await Interface.fetch_system_interfaces(connection)
        updated_interface = Interface.find_interface_by_name(
            updated_interfaces, self.name
        )
        assert updated_interface, f"Self (interface) not found in {updated_interfaces}"
        self.__state = updated_interface.state

    def __repr__(self):
        return (
            f"Interface(name={self.name!r}, state={self.__state}, ipv4={self.ipv4!r})"
        )

    @staticmethod
    async def get_enabled_network_interfaces(
        connection: Connection,
    ) -> List["Interface"]:
        interfaces = await Interface.fetch_system_interfaces(connection)

        # Find addresses for enabled interfaces (except loopback)
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
            ipv4_address = ipv4_match.group(1).strip() if ipv4_match else None

            interface = Interface.find_interface_by_name(interfaces, name)
            if interface:
                if interface.state is not InterfaceState.Enabled and ipv4_address:
                    raise ValueError(
                        f"Disabled interface with address assigned: {interface}, {ipv4_address}"
                    )
                interface.ipv4 = ipv4_address
            else:
                # Sometimes the interface doesn't show up already on show interface command
                interfaces.append(Interface(name, InterfaceState.Enabled, ipv4_address))
                log.debug("Added interface: %s, %s", name, ipv4_address)

        return interfaces

    @staticmethod
    async def fetch_system_interfaces(connection: Connection) -> List["Interface"]:
        process = await connection.create_process(
            ["netsh", "interface", "show", "interface"], quiet=True
        ).execute()

        stdout = process.get_stdout()
        log.debug("[%s]: %s", connection.tag, stdout)

        interfaces: List[Interface] = []
        matches = re.finditer(
            r"(Disabled|Enabled)(?:[\s]+[\w]+[\s]+){2}(.*$)",
            stdout,
            re.MULTILINE,
        )
        for match in matches:
            name = match.group(2).strip()
            if match.group(1).strip() == "Enabled":
                ifc = Interface(name, InterfaceState.Enabled)
            elif match.group(1).strip() == "Disabled":
                ifc = Interface(name, InterfaceState.Disabled)
            else:
                raise ValueError("Unknown Windows NIC state")

            interfaces.append(ifc)

        return interfaces

    @staticmethod
    def find_interface_by_name(
        interfaces: list["Interface"], name: str
    ) -> Optional["Interface"]:
        if not interfaces:
            raise ValueError("Empty interfaces list")
        return next((iface for iface in interfaces if iface.name == name), None)

    @staticmethod
    def find_interface_by_ipv4(
        interfaces: list["Interface"], prefix: str
    ) -> Optional["Interface"]:
        if not interfaces:
            raise ValueError("Empty interfaces list")
        return next(
            (
                iface
                for iface in interfaces
                if iface.ipv4 and iface.ipv4.startswith(prefix)
            ),
            None,
        )

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
            raise RuntimeError("Failed to disable management interface")

        if await self.get_state(connection) is InterfaceState.Enabled:
            raise RuntimeError(
                "Tried to disable but system still reports it as enabled"
            )

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
            for iface in await Interface.get_enabled_network_interfaces(connection)
            if self.name == iface.name and iface.ipv4
        ]):
            await asyncio.sleep(0.5)


class NetworkSwitcherWindows(NetworkSwitcher):
    def __init__(
        self,
        connection: Connection,
        primary_ifc: Interface,
        secondary_ifc: Interface,
    ) -> None:
        self._connection = connection
        self._primary_interface = primary_ifc
        self._secondary_interface = secondary_ifc

    @staticmethod
    async def create(connection: Connection) -> "NetworkSwitcherWindows":
        interfaces = await Interface.get_enabled_network_interfaces(connection)

        # Allow management interface to be shut down
        primary_itf = Interface.find_interface_by_ipv4(
            interfaces, config.LAN_ADDR_MAP[connection.tag]["primary"]
        )
        secondary_itf = Interface.find_interface_by_ipv4(
            interfaces, config.LAN_ADDR_MAP[connection.tag]["secondary"]
        )
        assert (
            primary_itf
        ), f"Couldn't find primary VM interface on the interfaces list: {interfaces}"
        assert (
            secondary_itf
        ), f"Couldn't find secondary VM interface on the interfaces list: {interfaces}"

        return NetworkSwitcherWindows(
            connection,
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
            timeout=STATUS_CHECK_TIMEOUT_S,
        ).check_exists(
            "0.0.0.0/0",
            [
                config.GW_ADDR_MAP[self._connection.tag]["primary"],
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
            timeout=STATUS_CHECK_TIMEOUT_S,
        ).check_exists(
            "0.0.0.0/0",
            [
                config.GW_ADDR_MAP[self._connection.tag]["secondary"],
            ],
        ):
            raise Exception("Failed to switch to secondary network")

    async def _delete_existing_routes(self) -> None:
        # Deleting routes by interface name instead of network destination (0.0.0.0/0) makes
        # it possible to have multiple default routes at the same time: first default route
        # for LAN network, and second default route for VPN network.
        await self._primary_interface.delete_route(self._connection)
        await self._secondary_interface.delete_route(self._connection)
