import re
from .linux_router import (
    LinuxRouter,
    ROUTING_TABLE_ID,
    FWMARK_VALUE,
    VPN_TABLE_V4_NETWORKS,
)
from .router import IPStack
from tests import config
from tests.utils.connection import Connection
from tests.utils.logger import log
from tests.utils.process import ProcessExecError

# Android's netd owns ip-rule priorities 10000-32000 (including a catch-all
# `32000: from all unreachable`), so a rule at LinuxRouter's ROUTING_PRIORITY
# (32111) never matches. Install the VPN rule below that range instead.
ANDROID_ROUTING_PRIORITY = "5000"


class AndroidRouter(LinuxRouter):
    """Android shares the Linux userland (iptables/ip), so most routing is
    inherited from LinuxRouter. Only the VPN route differs: netd-managed policy
    routing and the absence of VpnService fwmark protection need a lower rule
    priority and an explicit server-subnet bypass. IPv4-only (the android kernel
    has no ip6tables nat table). LLT-4141."""

    def __init__(self, connection: Connection, ip_stack: IPStack) -> None:
        assert (
            ip_stack == IPStack.IPv4
        ), "AndroidRouter is IPv4-only (android has no ip6tables nat table)"
        super().__init__(connection, ip_stack)

    async def create_vpn_route(self):
        # libtelio's WG socket isn't fwmark-protected without a VpnService, so
        # the encrypted packets to the VPN server (which sits inside 10.0.0.0/16)
        # would loop back into the tun. Resolve the server subnet's physical path
        # first, then pin it out the underlying link.
        proc = await self._connection.create_process(
            ["ip", "route", "get", config.VPN_SERVER_SUBNET.split("/", maxsplit=1)[0]],
            quiet=True,
        ).execute()
        via = re.search(r"\bvia (\S+)", proc.get_stdout())
        dev = re.search(r"\bdev (\S+)", proc.get_stdout())
        assert dev, f"no physical route to VPN server: {proc.get_stdout()}"

        bypass = ["ip", "route", "add", config.VPN_SERVER_SUBNET]
        if via:
            bypass += ["via", via.group(1)]
        bypass += ["dev", dev.group(1), "table", ROUTING_TABLE_ID]

        tunnel_routes = [
            [
                "ip",
                "route",
                "add",
                net,
                "dev",
                self._interface_name,
                "table",
                ROUTING_TABLE_ID,
            ]
            for net in VPN_TABLE_V4_NETWORKS
        ]
        for cmd in [*tunnel_routes, bypass]:
            try:
                await self._connection.create_process(cmd).execute()
            except ProcessExecError as exception:
                if exception.stderr.find("File exists") < 0:
                    raise exception
                log.warning(exception.stderr)

        await self._connection.create_process([
            "ip",
            "rule",
            "add",
            "priority",
            ANDROID_ROUTING_PRIORITY,
            "not",
            "from",
            "all",
            "fwmark",
            FWMARK_VALUE,
            "lookup",
            ROUTING_TABLE_ID,
        ]).execute()

    async def delete_vpn_route(self):
        for cmd in (
            ["ip", "rule", "del", "priority", ANDROID_ROUTING_PRIORITY],
            ["ip", "route", "del", config.VPN_SERVER_SUBNET, "table", ROUTING_TABLE_ID],
        ):
            try:
                await self._connection.create_process(cmd, quiet=True).execute()
            except ProcessExecError as exception:
                if exception.stderr.find("No such") < 0:
                    raise exception
                log.warning(exception.stderr)
