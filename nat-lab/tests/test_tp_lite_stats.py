import asyncio
import pytest
from tests import config
from tests.helpers import SetupParameters, Environment, Connection
from tests.helpers_vpn import connect_vpn
from tests.utils.bindings import (
    default_features,
    TelioAdapterType,
    TpLiteStatsOptions,
    FeatureFirewall,
    DnsRedirect,
)
from tests.utils.connection import ConnectionTag
from tests.utils.dns import query_dns
from typing import Optional

TP_LITE_DNS_IP = config.TP_LITE_DNS_SERVER_IP

# Blocked on TP-Lite server via NXDOMAIN + SOA
BLOCKED_NXDOMAIN = "blocked-malware.com"
# Blocked on TP-Lite server via A(0.0.0.0) + SOA
BLOCKED_NULL_IP = "blocked-ads.com"
# Resolves normally on the TP-Lite server
ALLOWED_DOMAIN = "google.com"

# Standard (non-blocking) DNS server. Unlike the TP-Lite server it resolves
# blocked-malware.com instead of returning NXDOMAIN.
STANDARD_DNS_IP = config.LAN_ADDR_MAP[ConnectionTag.DOCKER_DNS_SERVER_1]["primary"]
# Address the standrd dns-server returns for blocked-malware.com
WHITELIST_RESOLVED_IP = "123.123.123.123"

CALLBACK_INTERVAL_S = 1  # Use short interval for all tests


def _features_with_firewall():
    features = default_features()
    features.firewall = FeatureFirewall(
        neptun_reset_conns=False,
        boringtun_reset_conns=False,
        exclude_private_ip_range=None,
        outgoing_blacklist=[],
    )
    return features


def _tp_lite_config(dns_server_ips: Optional[list[str]] = None):
    return TpLiteStatsOptions(
        dns_server_ips=(
            dns_server_ips if dns_server_ips is not None else [TP_LITE_DNS_IP]
        ),
        callback_interval_s=CALLBACK_INTERVAL_S,
        blocked_domains_buffer_size=None,
        cache_size=None,
        max_open_requests=None,
        force_plaintext_dns=None,
    )


# Stats collection happens on packet processing, after a certain timeout
# To trigger, wait for the callback interval duration and then send a packet
#
# Here the standard, non-TP-Lite server is used to not have the collection trigger
# be part of the collected stats
async def _trigger_stats_collection(
    connection: Connection,
):
    default_dns_ip = config.LAN_ADDR_MAP[ConnectionTag.DOCKER_DNS_SERVER_1]["primary"]

    await asyncio.sleep(CALLBACK_INTERVAL_S + 1)
    await query_dns(
        connection, ALLOWED_DOMAIN, dns_server=default_dns_ip, options=["-type=a"]
    )


def _alpha_setup_params_with_firewall() -> SetupParameters:
    return SetupParameters(
        connection_tag=ConnectionTag.DOCKER_CONE_CLIENT_1,
        adapter_type_override=TelioAdapterType.NEP_TUN,
        features=_features_with_firewall(),
    )


def _alpha_setup_params_default() -> SetupParameters:
    return SetupParameters(
        connection_tag=ConnectionTag.DOCKER_CONE_CLIENT_1,
        adapter_type_override=TelioAdapterType.NEP_TUN,
        features=default_features(),
    )


class TestTpLiteStats:
    """TP-Lite stats collection — all tests share a single-node + VPN_1 setup."""

    @pytest.fixture(name="vpn_tags")
    def _vpn_tags(self) -> list:
        return [ConnectionTag.DOCKER_VPN_1]

    @pytest.mark.parametrize(
        "alpha_setup_params",
        [pytest.param(_alpha_setup_params_with_firewall())],
    )
    @pytest.mark.asyncio
    async def test_tp_lite_stats_basic(
        self,
        alpha_setup_params: SetupParameters,  # pylint: disable=unused-argument
        env: Environment,
    ) -> None:
        [alpha] = env.nodes
        [client] = env.clients
        [connection] = [c.connection for c in env.connections]
        standard_dns_ip = config.LAN_ADDR_MAP[ConnectionTag.DOCKER_DNS_SERVER_1][
            "primary"
        ]

        await connect_vpn(
            connection,
            None,
            client,
            alpha.ip_addresses[0],
            config.WG_SERVER,
        )

        await client.enable_tp_lite_stats_collection(_tp_lite_config())

        await query_dns(
            connection, ALLOWED_DOMAIN, dns_server=TP_LITE_DNS_IP, options=["-type=a"]
        )

        # Query blocked domain
        with pytest.raises(Exception):
            await query_dns(
                connection,
                BLOCKED_NXDOMAIN,
                dns_server=TP_LITE_DNS_IP,
                options=["-type=a"],
            )
        # Query same blocked domain again to trigger a cache hit
        with pytest.raises(Exception):
            await query_dns(
                connection,
                BLOCKED_NXDOMAIN,
                dns_server=TP_LITE_DNS_IP,
                options=["-type=a"],
            )
        # Query same domain but with the non-TP-Lite DNS server
        # Does not get logged in blocked domains or metrics
        await query_dns(
            connection,
            BLOCKED_NXDOMAIN,
            dns_server=standard_dns_ip,
            options=["-type=a"],
        )

        # Query blocked domain with different blocking mechanism
        # This should succeed at the DNS level (NOERROR) but be reported as blocked
        await query_dns(
            connection, BLOCKED_NULL_IP, dns_server=TP_LITE_DNS_IP, options=["-type=a"]
        )

        await _trigger_stats_collection(connection)
        (num_calls, domains, metrics) = await client.get_tp_lite_stats()

        blocked_domain_names = [d.domain_name for d in domains]

        assert num_calls == 1
        assert metrics.num_requests == 4
        assert metrics.num_responses == 4
        assert metrics.num_cache_hits == 1

        assert BLOCKED_NXDOMAIN in blocked_domain_names
        nxdomain_entry = next(d for d in domains if d.domain_name == BLOCKED_NXDOMAIN)
        assert "malware" in nxdomain_entry.category.lower()

        assert BLOCKED_NULL_IP in blocked_domain_names
        null_ip_entry = next(d for d in domains if d.domain_name == BLOCKED_NULL_IP)
        assert "ads-and-trackers" in null_ip_entry.category.lower()

        assert ALLOWED_DOMAIN not in blocked_domain_names

        await client.disable_tp_lite_stats_collection()

        # Make query after disabling, should not trigger callback
        with pytest.raises(Exception):
            await query_dns(
                connection,
                BLOCKED_NXDOMAIN,
                dns_server=TP_LITE_DNS_IP,
                options=["-type=a"],
            )

        await _trigger_stats_collection(connection)
        (num_calls, _, _) = await client.get_tp_lite_stats()
        assert num_calls == 0

    @pytest.mark.parametrize(
        "alpha_setup_params",
        [pytest.param(_alpha_setup_params_with_firewall())],
    )
    @pytest.mark.asyncio
    async def test_tp_lite_stats_re_enable_with_new_callback(
        self,
        alpha_setup_params: SetupParameters,  # pylint: disable=unused-argument
        env: Environment,
    ) -> None:
        [alpha] = env.nodes
        [client] = env.clients
        [connection] = [c.connection for c in env.connections]

        await connect_vpn(
            connection,
            None,
            client,
            alpha.ip_addresses[0],
            config.WG_SERVER,
        )

        for _ in range(2):
            await client.enable_tp_lite_stats_collection(_tp_lite_config())

            await _trigger_stats_collection(connection)
            (num_calls, _, _) = await client.get_tp_lite_stats()
            assert num_calls == 0

            with pytest.raises(Exception):
                await query_dns(
                    connection,
                    BLOCKED_NXDOMAIN,
                    dns_server=TP_LITE_DNS_IP,
                    options=["-type=a"],
                )

            await _trigger_stats_collection(connection)
            (num_calls, domains, metrics) = await client.get_tp_lite_stats()

            assert num_calls == 1
            blocked_domain_names = [d.domain_name for d in domains]
            assert BLOCKED_NXDOMAIN in blocked_domain_names
            assert metrics.num_requests == 1
            assert metrics.num_responses == 1

    @pytest.mark.parametrize(
        "alpha_setup_params",
        [pytest.param(_alpha_setup_params_with_firewall())],
    )
    @pytest.mark.asyncio
    async def test_tp_lite_stats_empty_dns_server_ips_disables(
        self,
        alpha_setup_params: SetupParameters,  # pylint: disable=unused-argument
        env: Environment,
    ) -> None:
        [alpha] = env.nodes
        [client] = env.clients
        [connection] = [c.connection for c in env.connections]

        await connect_vpn(
            connection,
            None,
            client,
            alpha.ip_addresses[0],
            config.WG_SERVER,
        )

        # Attempt to enable TP-Lite stats with empty list of DNS servers, gives an exception
        with pytest.raises(Exception):
            await client.enable_tp_lite_stats_collection(
                _tp_lite_config(dns_server_ips=[])
            )

    @pytest.mark.parametrize(
        "alpha_setup_params",
        [pytest.param(_alpha_setup_params_default())],
    )
    @pytest.mark.asyncio
    async def test_tp_lite_stats_requires_firewall_feature(
        self,
        alpha_setup_params: SetupParameters,  # pylint: disable=unused-argument
        env: Environment,
    ) -> None:
        [alpha] = env.nodes
        [client] = env.clients
        [connection] = [c.connection for c in env.connections]

        await connect_vpn(
            connection,
            None,
            client,
            alpha.ip_addresses[0],
            config.WG_SERVER,
        )

        # Attempt to enable TP-Lite stats without firewall feature, gives an exception
        with pytest.raises(Exception):
            await client.enable_tp_lite_stats_collection(_tp_lite_config())


class TestDnsWhitelisting:
    """DNS whitelisting redirects whitelisted queries away from the blocking
    (TP-Lite) DNS server to a standard one via libfirewall DNAT."""

    @pytest.fixture(name="vpn_tags")
    def _vpn_tags(self) -> list:
        return [ConnectionTag.DOCKER_VPN_1]

    @pytest.mark.parametrize(
        "alpha_setup_params",
        [
            pytest.param(
                SetupParameters(
                    connection_tag=ConnectionTag.DOCKER_CONE_CLIENT_1,
                    adapter_type_override=TelioAdapterType.NEP_TUN,
                    features=_features_with_firewall(),
                )
            )
        ],
    )
    @pytest.mark.asyncio
    @pytest.mark.libfirewall
    async def test_dns_whitelisting_redirects_blocked_domain(
        self,
        alpha_setup_params: SetupParameters,  # pylint: disable=unused-argument
        env: Environment,
    ) -> None:
        [alpha] = env.nodes
        [client] = env.clients
        [connection] = [c.connection for c in env.connections]

        await connect_vpn(
            connection,
            None,
            client,
            alpha.ip_addresses[0],
            config.WG_SERVER,
        )

        # Before whitelisting any domain at runtime, the query hits the blocking
        # (TP-Lite) server and returns NXDOMAIN - it is not redirected.
        with pytest.raises(Exception):
            await query_dns(
                connection,
                BLOCKED_NXDOMAIN,
                dns_server=TP_LITE_DNS_IP,
                options=["-type=a"],
            )

        # Configure the whitelist and the DNS redirect at runtime, which
        # reconfigures the firewall.
        await client.set_tp_lite_domain_whitelist(
            [BLOCKED_NXDOMAIN],
            [
                DnsRedirect(
                    blocking=f"{TP_LITE_DNS_IP}:53",
                    standard=f"{STANDARD_DNS_IP}:53",
                )
            ],
        )

        # blocked-malware.com is NXDOMAIN at the TP-Lite (blocking) server, but it
        # is now whitelisted, so the firewall DNATs the query to the standard DNS
        # server, which resolves it to WHITELIST_RESOLVED_IP. Getting that address
        # back proves the query was redirected.
        await query_dns(
            connection,
            BLOCKED_NXDOMAIN,
            dns_server=TP_LITE_DNS_IP,
            expected_output=[WHITELIST_RESOLVED_IP],
            options=["-type=a"],
        )

        # A domain that is NOT whitelisted still hits the blocking server, which
        # returns NXDOMAIN for it, confirming the redirect is scoped to the
        # whitelisted domains only.
        with pytest.raises(Exception):
            await query_dns(
                connection,
                "not-whitelisted.com",
                dns_server=TP_LITE_DNS_IP,
                options=["-type=a"],
            )
