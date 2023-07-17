from utils.connection import Connection
from utils.process import ProcessExecError
from contextlib import asynccontextmanager
from typing import AsyncIterator, List
from utils import Router, IPStack, IPProto

# An arbitrary routing table id. Must be unique on the system.
ROUTING_TABLE_ID = "73110"  # TELIO

# An arbitrary fwmark value. Must be unique on the system. Also defined in tcli/src/cli.rs
FWMARK_VALUE = "11673110"  # LIBTELIO

# This value needs to be between `local` and `main` routing policy rules.
# Must be unique on the system.
# > ip rule
# 0:  from all lookup local
# 32766:  from all lookup main
# 32767:  from all lookup default
ROUTING_PRIORITY = "32111"


class LinuxRouter(Router):
    _connection: Connection
    _interface_name: str

    def __init__(self, connection: Connection):
        super().__init__()
        self._connection = connection
        self._interface_name = "tun10"

    def get_interface_name(self) -> str:
        return self._interface_name

    async def setup_interface(self, addresses: List[str]) -> None:
        for address in addresses:
            addr_proto = self.check_ip_address(address)

            if addr_proto == IPProto.IPv4:
                await self._connection.create_process(
                    [
                        "ip",
                        "-4",
                        "addr",
                        "add",
                        "dev",
                        self._interface_name,
                        address,
                    ],
                ).execute()
            elif addr_proto == IPProto.IPv6:
                await self._connection.create_process(
                    [
                        "ip",
                        "-6",
                        "addr",
                        "add",
                        address,
                        "dev",
                        self._interface_name,
                    ],
                ).execute()
            else:
                continue

        await self._connection.create_process(
            ["ip", "link", "set", "up", "dev", self._interface_name],
        ).execute()

    async def create_meshnet_route(self):
        if self.ip_stack == IPStack.IPv4 or self.ip_stack == IPStack.IPv4v6:
            await self._connection.create_process(
                [
                    "ip",
                    "-4",
                    "route",
                    "add",
                    "100.64.0.0/10",
                    "dev",
                    self._interface_name,
                ],
            ).execute()

        if self.ip_stack == IPStack.IPv6 or self.ip_stack == IPStack.IPv4v6:
            await self._connection.create_process(
                [
                    "ip",
                    "-6",
                    "route",
                    "add",
                    "fd00::/64",  # TODO correct subnet when we'll decide about the range
                    "dev",
                    self._interface_name,
                ],
            ).execute()

    async def create_vpn_route(self):
        if self.ip_stack == IPStack.IPv6:
            assert False, f"IPv6 for VPN is not supported"

        try:
            await self._connection.create_process(
                [
                    "ip",
                    "route",
                    "add",
                    "10.0.0.0/16",
                    "dev",
                    self._interface_name,
                    "table",
                    ROUTING_TABLE_ID,
                ],
            ).execute()
        except ProcessExecError as exception:
            if exception.stderr.find("File exists") < 0:
                raise exception

        try:
            await self._connection.create_process(
                [
                    "ip",
                    "route",
                    "add",
                    "100.64.0.1",
                    "dev",
                    self._interface_name,
                    "table",
                    ROUTING_TABLE_ID,
                ],
            ).execute()
        except ProcessExecError as exception:
            if exception.stderr.find("File exists") < 0:
                raise exception

        await self._connection.create_process(
            [
                "ip",
                "rule",
                "add",
                "priority",
                ROUTING_PRIORITY,
                "not",
                "from",
                "all",
                "fwmark",
                FWMARK_VALUE,
                "lookup",
                ROUTING_TABLE_ID,
            ],
        ).execute()

    async def delete_interface(self) -> None:
        try:
            await self._connection.create_process(
                ["ip", "link", "delete", self._interface_name]
            ).execute()
        except ProcessExecError as exception:
            if exception.stderr.find("Cannot find device") < 0:
                raise exception

    async def delete_vpn_route(self):
        if self.ip_stack == IPStack.IPv6:
            assert False, f"IPv6 for VPN is not supported"

        try:
            await self._connection.create_process(
                [
                    "ip",
                    "rule",
                    "del",
                    "priority",
                    ROUTING_PRIORITY,
                ],
            ).execute()
        except ProcessExecError as exception:
            if (
                exception.stderr.find("RTNETLINK answers: No such file or directory")
                < 0
            ):
                raise exception

    async def create_exit_node_route(self) -> None:
        if self.ip_stack == IPStack.IPv4 or self.ip_stack == IPStack.IPv4v6:
            await self._connection.create_process(
                [
                    "iptables",
                    "-t",
                    "nat",
                    "-A",
                    "POSTROUTING",
                    "-s",
                    "100.64.0.0/10",
                    "!",
                    "-o",
                    self._interface_name,
                    "-j",
                    "MASQUERADE",
                ],
            ).execute()

        if self.ip_stack == IPStack.IPv6 or self.ip_stack == IPStack.IPv4v6:
            await self._connection.create_process(
                [
                    "ip6tables",
                    "-t",
                    "nat",
                    "-A",
                    "POSTROUTING",
                    "-s",
                    "fd00::/64",  # TODO correct subnet when we'll decide about the range
                    "!",
                    "-o",
                    self._interface_name,
                    "-j",
                    "MASQUERADE",
                ],
            ).execute()

    async def delete_exit_node_route(self) -> None:
        if self.ip_stack == IPStack.IPv4 or self.ip_stack == IPStack.IPv4v6:
            try:
                await self._connection.create_process(
                    [
                        "iptables",
                        "-t",
                        "nat",
                        "-D",
                        "POSTROUTING",
                        "-s",
                        "100.64.0.0/10",
                        "!",
                        "-o",
                        self._interface_name,
                        "-j",
                        "MASQUERADE",
                    ],
                ).execute()
            except ProcessExecError as exception:
                if exception.stderr.find("No chain/target/match by that name") < 0:
                    raise exception

        if self.ip_stack == IPStack.IPv6 or self.ip_stack == IPStack.IPv4v6:
            try:
                await self._connection.create_process(
                    [
                        "ip6tables",
                        "-t",
                        "nat",
                        "-D",
                        "POSTROUTING",
                        "-s",
                        "fd00::/64",  # TODO correct subnet when we'll decide about the range
                        "!",
                        "-o",
                        self._interface_name,
                        "-j",
                        "MASQUERADE",
                    ],
                ).execute()
            except ProcessExecError as exception:
                if (
                    exception.stderr.find(
                        "Bad rule (does a matching rule exist in that chain?)"
                    )
                    < 0
                ):
                    raise exception

    @asynccontextmanager
    async def disable_path(self, address: str) -> AsyncIterator:
        addr_proto = self.check_ip_address(address)

        if addr_proto == None:
            return

        await self._connection.create_process(
            [
                ("ip" if addr_proto == IPProto.IPv4 else "ip6") + "tables",
                "-t",
                "filter",
                "-A",
                "INPUT",
                "-s",
                address,
                "-j",
                "DROP",
            ]
        ).execute()
        await self._connection.create_process(
            [
                ("ip" if addr_proto == IPProto.IPv4 else "ip6") + "tables",
                "-t",
                "filter",
                "-A",
                "OUTPUT",
                "-d",
                address,
                "-j",
                "DROP",
            ]
        ).execute()

        try:
            yield
        finally:
            await self._connection.create_process(
                [
                    ("ip" if addr_proto == IPProto.IPv4 else "ip6") + "tables",
                    "-t",
                    "filter",
                    "-D",
                    "INPUT",
                    "-s",
                    address,
                    "-j",
                    "DROP",
                ]
            ).execute()
            await self._connection.create_process(
                [
                    ("ip" if addr_proto == IPProto.IPv4 else "ip6") + "tables",
                    "-t",
                    "filter",
                    "-D",
                    "OUTPUT",
                    "-d",
                    address,
                    "-j",
                    "DROP",
                ]
            ).execute()

    @asynccontextmanager
    async def break_tcp_conn_to_host(self, address: str) -> AsyncIterator:
        addr_proto = self.check_ip_address(address)

        if addr_proto == None:
            return

        await self._connection.create_process(
            [
                ("ip" if addr_proto == IPProto.IPv4 else "ip6") + "tables",
                "-t",
                "filter",
                "-A",
                "OUTPUT",
                "--destination",
                address,
                "-p",
                "tcp",
                "-j",
                "REJECT",
                "--reject-with",
                "tcp-reset",
            ]
        ).execute()

        try:
            yield
        finally:
            await self._connection.create_process(
                [
                    ("ip" if addr_proto == IPProto.IPv4 else "ip6") + "tables",
                    "-t",
                    "filter",
                    "-D",
                    "OUTPUT",
                    "--destination",
                    address,
                    "-p",
                    "tcp",
                    "-j",
                    "REJECT",
                    "--reject-with",
                    "tcp-reset",
                ]
            ).execute()
