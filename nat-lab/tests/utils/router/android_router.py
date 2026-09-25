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
from typing import List, Optional

# Android's netd owns ip-rule priorities 10000-32000 (including a catch-all
# `32000: from all unreachable`), so a rule at LinuxRouter's ROUTING_PRIORITY
# (32111) never matches. Install the rule below that range instead.
ANDROID_ROUTING_PRIORITY = "5000"

# libtelio's sockets are unmarked without a VpnService, so its encrypted traffic
# would follow the 10.0.0.0/16 tunnel route into tun10 and loop.
BYPASS_SUBNETS = [config.VPN_SERVER_SUBNET, config.DERP_SERVER_SUBNET]

# 100.64.0.1 is the VPN peer; magic DNS answers on 100.64.0.2. Linux reaches it
# through the main table's connected route from the tun address, but netd bypasses
# the main table, so Android needs the whole range in ROUTING_TABLE_ID.
VPN_TUNNEL_NETWORKS = [
    config.LIBTELIO_IPV4_WG_SUBNET if net == "100.64.0.1" else net
    for net in VPN_TABLE_V4_NETWORKS
]


class AndroidRouter(LinuxRouter):
    """Android shares the Linux userland (iptables/ip), so most routing is
    inherited from LinuxRouter. The meshnet and VPN routes differ: netd-managed
    policy routing and the absence of VpnService fwmark protection need a lower
    rule priority and explicit infrastructure-subnet bypasses. IPv4-only (the
    android kernel has no ip6tables nat table). LLT-4141."""

    def __init__(self, connection: Connection, ip_stack: IPStack) -> None:
        assert (
            ip_stack == IPStack.IPv4
        ), "AndroidRouter is IPv4-only (android has no ip6tables nat table)"
        super().__init__(connection, ip_stack)
        self._policy_rule_added = False
        self._meshnet_route_created = False
        self._physical_hop: Optional[List[str]] = None

    async def _run_tolerating(self, command: List[str], tolerated: str) -> None:
        try:
            await self._connection.create_process(command).execute()
        except ProcessExecError as exception:
            if exception.stderr.find(tolerated) < 0:
                raise exception
            log.warning(exception.stderr)

    async def _add_table_routes(self, networks: List[str]) -> None:
        for network in networks:
            await self._run_tolerating(
                [
                    "ip",
                    "route",
                    "add",
                    network,
                    "dev",
                    self._interface_name,
                    "table",
                    ROUTING_TABLE_ID,
                ],
                "File exists",
            )

    async def _delete_table_routes(self, networks: List[str]) -> None:
        for network in networks:
            await self._run_tolerating(
                ["ip", "route", "del", network, "table", ROUTING_TABLE_ID],
                "No such",
            )

    async def _add_bypass_routes(self) -> None:
        if self._physical_hop is None:
            proc = await self._connection.create_process(
                [
                    "ip",
                    "route",
                    "get",
                    config.VPN_SERVER_SUBNET.split("/", maxsplit=1)[0],
                ],
                quiet=True,
            ).execute()
            via = re.search(r"\bvia (\S+)", proc.get_stdout())
            dev = re.search(r"\bdev (\S+)", proc.get_stdout())
            assert dev, f"no physical route to VPN server: {proc.get_stdout()}"
            assert (
                dev.group(1) != self._interface_name
            ), f"physical route to VPN server resolved to the tunnel: {proc.get_stdout()}"
            hop = ["via", via.group(1)] if via else []
            self._physical_hop = hop + ["dev", dev.group(1)]

        for subnet in BYPASS_SUBNETS:
            await self._run_tolerating(
                [
                    "ip",
                    "route",
                    "add",
                    subnet,
                    *self._physical_hop,
                    "table",
                    ROUTING_TABLE_ID,
                ],
                "File exists",
            )

    async def _add_policy_rule(self) -> None:
        if self._policy_rule_added:
            return
        await self._run_tolerating(
            [
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
            ],
            "File exists",
        )
        self._policy_rule_added = True

    async def _delete_policy_rule(self) -> None:
        if not self._policy_rule_added:
            return
        await self._run_tolerating(
            ["ip", "rule", "del", "priority", ANDROID_ROUTING_PRIORITY],
            "No such",
        )
        self._policy_rule_added = False

    async def create_meshnet_route(self):
        await self._add_table_routes([config.LIBTELIO_IPV4_WG_SUBNET])
        await self._add_policy_rule()
        self._meshnet_route_created = True

    async def create_vpn_route(self):
        await self._add_table_routes(VPN_TUNNEL_NETWORKS)
        await self._add_bypass_routes()
        await self._add_policy_rule()

    async def delete_vpn_route(self):
        stale = [
            net
            for net in VPN_TUNNEL_NETWORKS
            if not (
                net == config.LIBTELIO_IPV4_WG_SUBNET and self._meshnet_route_created
            )
        ]
        await self._delete_table_routes(stale + BYPASS_SUBNETS)

        if not self._meshnet_route_created:
            await self._delete_policy_rule()
