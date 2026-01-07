import random
from .router import Router, IPProto, IPStack
from contextlib import asynccontextmanager
from tests.config import LIBTELIO_IPV6_WG_SUBNET
from tests.utils.command_grepper import CommandGrepper
from tests.utils.connection import Connection
from tests.utils.process import ProcessExecError
from typing import AsyncIterator, List


class WindowsRouter(Router):
    _connection: Connection
    _interface_name: str
    # The average time it takes to set up an interface on Windows is ~3 seconds
    _status_check_timeout_s: float = 30.0

    def __init__(self, connection: Connection, ip_stack: IPStack):
        super().__init__(ip_stack)
        self._connection = connection
        self._interface_name = "wintun10_" + str(random.randint(0, 256))

    def get_interface_name(self) -> str:
        return self._interface_name

    async def setup_interface(self, addresses: List[str]) -> None:
        assert self._interface_name

        for address in addresses:
            addr_proto = self.check_ip_address(address)

            # Disable Duplicate Address detection on tunnel interface
            cmd = CommandGrepper(
                self._connection,
                [
                    "netsh",
                    "interface",
                    "ipv4" if addr_proto == IPProto.IPv4 else "ipv6",
                    "set",
                    "interface",
                    self._interface_name,
                    "dadtransmits=0",
                ],
                timeout=self._status_check_timeout_s,
                allow_process_failure=True,
            )
            if not await cmd.check_exists("Ok"):
                raise RuntimeError(
                    f"Failed to disable Duplicate Address Detection on Tunnel interface {self._interface_name}"
                )

            # Set address
            if addr_proto == IPProto.IPv4:
                await self._connection.create_process(
                    [
                        "netsh",
                        "interface",
                        "ipv4",
                        "add",
                        "address",
                        self._interface_name,
                        address,
                        "255.255.255.255",
                    ],
                    quiet=True,
                ).execute()
            elif addr_proto == IPProto.IPv6:
                await self._connection.create_process(
                    [
                        "netsh",
                        "interface",
                        "ipv6",
                        "add",
                        "address",
                        self._interface_name,
                        address + "/128",
                    ],
                    quiet=True,
                ).execute()

    async def deconfigure_interface(self, addresses: List[str]) -> None:
        for address in addresses:
            addr_proto = self.check_ip_address(address)

            if addr_proto == IPProto.IPv4:
                await self._connection.create_process(
                    [
                        "netsh",
                        "interface",
                        "ipv4",
                        "delete",
                        "address",
                        self._interface_name,
                        address,
                        "255.255.255.255",
                    ],
                    quiet=True,
                ).execute()
            elif addr_proto == IPProto.IPv6:
                await self._connection.create_process(
                    [
                        "netsh",
                        "interface",
                        "ipv6",
                        "delete",
                        "address",
                        self._interface_name,
                        address,
                    ],
                    quiet=True,
                ).execute()

    async def enable_interface(self) -> None:
        await self._connection.create_process(
            [
                "netsh",
                "interface",
                "set",
                "interface",
                self._interface_name,
                "admin=enable",
            ],
            quiet=True,
        ).execute()

    async def disable_interface(self) -> None:
        await self._connection.create_process(
            [
                "netsh",
                "interface",
                "set",
                "interface",
                self._interface_name,
                "admin=disable",
            ],
            quiet=True,
        ).execute()

    async def create_fake_ipv4_route(self, route: str) -> None:
        try:
            await self._connection.create_process(
                [
                    "netsh",
                    "interface",
                    "ipv4",
                    "add",
                    "route",
                    route,
                    self._interface_name,
                ],
                quiet=True,
            ).execute()
        except ProcessExecError as exception:
            if exception.stdout.find("The object already exists.") < 0:
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
            timeout=self._status_check_timeout_s,
        ).check_exists(route, [self._interface_name]):
            raise Exception("Failed to create fake ipv4 route")

    async def create_meshnet_route(self) -> None:
        if self.ip_stack in [IPStack.IPv4, IPStack.IPv4v6]:
            try:
                await self._connection.create_process(
                    [
                        "netsh",
                        "interface",
                        "ipv4",
                        "add",
                        "route",
                        "100.64.0.0/10",
                        self._interface_name,
                    ],
                    quiet=True,
                ).execute()
            except ProcessExecError as exception:
                if exception.stdout.find("The object already exists.") < 0:
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
                timeout=self._status_check_timeout_s,
            ).check_exists("100.64.0.0/10", [self._interface_name]):
                raise Exception("Failed to create ipv4 meshnet route")

        if self.ip_stack in [IPStack.IPv6, IPStack.IPv4v6]:
            try:
                await self._connection.create_process(
                    [
                        "netsh",
                        "interface",
                        "ipv6",
                        "add",
                        "route",
                        LIBTELIO_IPV6_WG_SUBNET + "::/64",
                        self._interface_name,
                    ],
                    quiet=True,
                ).execute()
            except ProcessExecError as exception:
                if exception.stdout.find("The object already exists.") < 0:
                    raise exception

            if not await CommandGrepper(
                self._connection,
                [
                    "netsh",
                    "interface",
                    "ipv6",
                    "show",
                    "route",
                ],
                timeout=self._status_check_timeout_s,
            ).check_exists(LIBTELIO_IPV6_WG_SUBNET + "::/64", [self._interface_name]):
                raise Exception("Failed to create ipv6 meshnet route")

    async def create_vpn_route(self) -> None:
        try:
            await self._connection.create_process([
                "netsh",
                "interface",
                "ipv4",
                "add",
                "route",
                "0.0.0.0/0",
                self._interface_name,
                "metric=1",
            ]).execute()
        except ProcessExecError as exception:
            if exception.stdout.find("The object already exists.") < 0:
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
            timeout=self._status_check_timeout_s,
        ).check_exists("0.0.0.0/0", [self._interface_name]):
            raise Exception("Failed to create ipv4 vpn route")

        try:
            await self._connection.create_process([
                "netsh",
                "interface",
                "ipv6",
                "add",
                "route",
                "::/0",
                self._interface_name,
            ]).execute()
        except ProcessExecError as exception:
            if exception.stdout.find("The object already exists.") < 0:
                raise exception

        if not await CommandGrepper(
            self._connection,
            [
                "netsh",
                "interface",
                "ipv6",
                "show",
                "route",
            ],
            timeout=self._status_check_timeout_s,
        ).check_exists("::/0", [self._interface_name]):
            raise Exception("Failed to create ipv6 vpn route")

    async def delete_interface(self, name=None) -> None:
        pass

    async def delete_vpn_route(self) -> None:
        assert self._interface_name

        if self.ip_stack in [IPStack.IPv4, IPStack.IPv4v6]:
            try:
                await self._connection.create_process(
                    [
                        "netsh",
                        "interface",
                        "ipv4",
                        "delete",
                        "route",
                        "0.0.0.0/0",
                        self._interface_name,
                    ],
                    quiet=True,
                ).execute()
            except ProcessExecError as exception:
                if (
                    exception.stdout.find(
                        "The filename, directory name, or volume label syntax is"
                        " incorrect."
                    )
                    < 0
                    and exception.stdout.find("Element not found.") < 0
                ):
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
                timeout=self._status_check_timeout_s,
            ).check_not_exists("0.0.0.0/0", [self._interface_name]):
                raise Exception("Failed to delete ipv4 vpn route")

        if self.ip_stack in [IPStack.IPv6, IPStack.IPv4v6]:
            try:
                await self._connection.create_process(
                    [
                        "netsh",
                        "interface",
                        "ipv6",
                        "delete",
                        "route",
                        "::/0",
                        self._interface_name,
                    ],
                    quiet=True,
                ).execute()
            except ProcessExecError as exception:
                if (
                    exception.stdout.find(
                        "The filename, directory name, or volume label syntax is"
                        " incorrect."
                    )
                    < 0
                    and exception.stdout.find("Element not found.") < 0
                ):
                    raise exception

            if not await CommandGrepper(
                self._connection,
                [
                    "netsh",
                    "interface",
                    "ipv6",
                    "show",
                    "route",
                ],
                timeout=self._status_check_timeout_s,
            ).check_not_exists("::/0", [self._interface_name]):
                raise Exception("Failed to delete ipv6 vpn route")

    async def create_exit_node_route(self) -> None:
        pass

    async def delete_exit_node_route(self) -> None:
        pass

    @asynccontextmanager
    async def disable_path(
        self, address: str  # pylint: disable=unused-argument
    ) -> AsyncIterator:
        yield

    @asynccontextmanager
    async def break_tcp_conn_to_host(
        self, address: str  # pylint: disable=unused-argument
    ) -> AsyncIterator:
        yield

    @asynccontextmanager
    async def break_udp_conn_to_host(
        self, address: str  # pylint: disable=unused-argument
    ) -> AsyncIterator:
        yield

    @asynccontextmanager
    async def block_udp_port(
        self, port: int  # pylint: disable=unused-argument
    ) -> AsyncIterator:
        yield

    @asynccontextmanager
    async def block_tcp_port(
        self, port: int  # pylint: disable=unused-argument
    ) -> AsyncIterator:
        yield

    @asynccontextmanager
    async def reset_upnpd(self) -> AsyncIterator:
        yield

    def set_interface_name(
        self, new_interface_name: str  # pylint: disable=unused-argument
    ) -> None:
        pass
