import config
from .router import Router, IPStack, IPProto
from contextlib import asynccontextmanager
from typing import AsyncIterator, List
from utils.connection import Connection
from utils.process import ProcessExecError

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
INTERFACE_NAME = "tun10"


class AddressError(Exception):
    address: str

    def __init__(self, address) -> None:
        self.address = address


class AddressTypeError(AddressError):
    pass


class LinuxRouter(Router):
    _connection: Connection
    _interface_name: str

    def __init__(self, connection: Connection, ip_stack: IPStack):
        super().__init__(ip_stack)
        self._connection = connection
        self._interface_name = INTERFACE_NAME

    def get_interface_name(self) -> str:
        return self._interface_name

    async def setup_interface(self, addresses: List[str]) -> None:
        for address in addresses:
            await self._connection.create_process(
                [
                    "ip",
                    ("-4" if self.check_ip_address(address) == IPProto.IPv4 else "-6"),
                    "addr",
                    "add",
                    address,
                    "dev",
                    self._interface_name,
                ],
            ).execute()

        await self._connection.create_process(
            ["ip", "link", "set", "up", "dev", self._interface_name]
        ).execute()

    async def create_meshnet_route(self):
        if self.ip_stack in [IPStack.IPv4, IPStack.IPv4v6]:
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

        if self.ip_stack in [IPStack.IPv6, IPStack.IPv4v6]:
            await self._connection.create_process(
                [
                    "ip",
                    "-6",
                    "route",
                    "add",
                    config.LIBTELIO_IPV6_WG_SUBNET + "::/64",
                    "dev",
                    self._interface_name,
                ],
            ).execute()

    async def create_vpn_route(self):
        if self.ip_stack in [IPStack.IPv4, IPStack.IPv4v6]:
            for network in ["10.0.0.0/16", "100.64.0.1", "10.5.0.0/16"]:
                try:
                    await self._connection.create_process([
                        "ip",
                        "route",
                        "add",
                        network,
                        "dev",
                        self._interface_name,
                        "table",
                        ROUTING_TABLE_ID,
                    ]).execute()
                except ProcessExecError as exception:
                    if exception.stderr.find("File exists") < 0:
                        raise exception

            await self._connection.create_process([
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
            ]).execute()

        if self.ip_stack in [IPStack.IPv6, IPStack.IPv4v6]:
            for network in [
                config.LIBTELIO_IPV6_WAN_SUBNET
                + "::/"
                + config.LIBTELIO_IPV6_WAN_SUBNET_SZ,
                config.LIBTELIO_IPV6_WG_SUBNET + "::1",
            ]:
                try:
                    await self._connection.create_process([
                        "ip",
                        "-6",
                        "route",
                        "add",
                        network,
                        "dev",
                        self._interface_name,
                        "table",
                        ROUTING_TABLE_ID,
                    ]).execute()
                except ProcessExecError as exception:
                    if exception.stderr.find("File exists") < 0:
                        raise exception

            await self._connection.create_process([
                "ip",
                "-6",
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
            ]).execute()

    async def delete_interface(self) -> None:
        try:
            await self._connection.create_process(
                ["ip", "link", "delete", self._interface_name]
            ).execute()
        except ProcessExecError as exception:
            if exception.stderr.find("Cannot find device") < 0:
                raise exception

    async def delete_vpn_route(self):
        if self.ip_stack in [IPStack.IPv4, IPStack.IPv4v6]:
            try:
                await self._connection.create_process(
                    ["ip", "rule", "del", "priority", ROUTING_PRIORITY]
                ).execute()
            except ProcessExecError as exception:
                if (
                    exception.stderr.find(
                        "RTNETLINK answers: No such file or directory"
                    )
                    < 0
                ):
                    raise exception

        if self.ip_stack in [IPStack.IPv6, IPStack.IPv4v6]:
            try:
                await self._connection.create_process(
                    ["ip", "-6", "rule", "del", "priority", ROUTING_PRIORITY]
                ).execute()
            except ProcessExecError as exception:
                if (
                    exception.stderr.find(
                        "RTNETLINK answers: No such file or directory"
                    )
                    < 0
                ):
                    raise exception

    async def create_exit_node_route(self) -> None:
        if self.ip_stack in [IPStack.IPv4, IPStack.IPv4v6]:
            await self._connection.create_process([
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
            ]).execute()

        if self.ip_stack in [IPStack.IPv6, IPStack.IPv4v6]:
            await self._connection.create_process(
                [
                    "ip6tables",
                    "-t",
                    "nat",
                    "-A",
                    "POSTROUTING",
                    "-s",
                    config.LIBTELIO_IPV6_WG_SUBNET + "::/64",
                    "!",
                    "-o",
                    self._interface_name,
                    "-j",
                    "MASQUERADE",
                ],
            ).execute()

    async def delete_exit_node_route(self) -> None:
        if self.ip_stack in [IPStack.IPv4, IPStack.IPv4v6]:
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

        if self.ip_stack in [IPStack.IPv6, IPStack.IPv4v6]:
            try:
                await self._connection.create_process(
                    [
                        "ip6tables",
                        "-t",
                        "nat",
                        "-D",
                        "POSTROUTING",
                        "-s",
                        config.LIBTELIO_IPV6_WG_SUBNET + "::/64",
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

        if addr_proto is None:
            pass

        iptables_string = ("ip" if addr_proto == IPProto.IPv4 else "ip6") + "tables"

        await self._connection.create_process([
            iptables_string,
            "-t",
            "filter",
            "-A",
            "INPUT",
            "-s",
            address,
            "-j",
            "DROP",
        ]).execute()
        await self._connection.create_process([
            iptables_string,
            "-t",
            "filter",
            "-A",
            "OUTPUT",
            "-d",
            address,
            "-j",
            "DROP",
        ]).execute()

        try:
            yield
        finally:
            await self._connection.create_process([
                iptables_string,
                "-t",
                "filter",
                "-D",
                "INPUT",
                "-s",
                address,
                "-j",
                "DROP",
            ]).execute()
            await self._connection.create_process([
                iptables_string,
                "-t",
                "filter",
                "-D",
                "OUTPUT",
                "-d",
                address,
                "-j",
                "DROP",
            ]).execute()

    @asynccontextmanager
    async def break_tcp_conn_to_host(self, address: str) -> AsyncIterator:
        addr_proto = self.check_ip_address(address)

        if addr_proto is None:
            raise AddressTypeError(address)

        iptables_string = ("ip" if addr_proto == IPProto.IPv4 else "ip6") + "tables"

        await self._connection.create_process([
            iptables_string,
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
        ]).execute()

        try:
            yield
        finally:
            await self._connection.create_process([
                iptables_string,
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
            ]).execute()

    @asynccontextmanager
    async def break_udp_conn_to_host(self, address: str) -> AsyncIterator:
        addr_proto = self.check_ip_address(address)

        if addr_proto is None:
            return

        iptables_string = ("ip" if addr_proto == IPProto.IPv4 else "ip6") + "tables"

        await self._connection.create_process([
            iptables_string,
            "-t",
            "filter",
            "-A",
            "OUTPUT",
            "--destination",
            address,
            "-p",
            "udp",
            "-j",
            "REJECT",
            "--reject-with",
            "icmp-host-unreachable",
        ]).execute()

        try:
            yield
        finally:
            await self._connection.create_process([
                iptables_string,
                "-t",
                "filter",
                "-D",
                "OUTPUT",
                "--destination",
                address,
                "-p",
                "udp",
                "-j",
                "REJECT",
                "--reject-with",
                "icmp-host-unreachable",
            ]).execute()

    # This function blocks outgoing data for a specific port to simulate permission denied error for the socket bound to that port.
    # It was added for LLT-4980, to test a specific code path in proxy.rs
    @asynccontextmanager
    async def block_udp_port(self, port: int) -> AsyncIterator:
        await self._connection.create_process([
            "iptables",
            "-A",
            "OUTPUT",
            "-p",
            "udp",
            "--sport",
            str(port),
            "-j",
            "DROP",
        ]).execute()

        try:
            yield
        finally:
            await self._connection.create_process([
                "iptables",
                "-D",
                "OUTPUT",
                "-p",
                "udp",
                "--sport",
                str(port),
                "-j",
                "DROP",
            ]).execute()

    @asynccontextmanager
    async def reset_upnpd(self) -> AsyncIterator:
        await self._connection.create_process(["killall", "upnpd"]).execute()
        await self._connection.create_process(["conntrack", "-F"]).execute()
        try:
            yield
        finally:
            await self._connection.create_process(["upnpd", "eth0", "eth1"]).execute()
