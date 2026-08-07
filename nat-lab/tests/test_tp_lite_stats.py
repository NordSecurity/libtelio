import asyncio
import pytest
from tests import config
from tests.helpers import SetupParameters, Environment, Connection
from tests.helpers_vpn import connect_vpn
from tests.utils import asyncio_util
from tests.utils.bindings import (
    default_features,
    TelioAdapterType,
    TpLiteStatsOptions,
    FeatureFirewall,
    DnsRedirect,
)
from tests.utils.connection import ConnectionTag
from tests.utils.dns import query_dns, query_dns_port
from tests.utils.logger import log
from tests.utils.process import ProcessExecError
from typing import Optional

TP_LITE_DNS_IP = config.TP_LITE_DNS_SERVER_IP

# Blocked on TP-Lite server via NXDOMAIN + SOA
BLOCKED_NXDOMAIN = "blocked-malware.com"
# Blocked on TP-Lite server via A(0.0.0.0) + SOA
BLOCKED_NULL_IP = "blocked-ads.com"
# Resolves normally on the TP-Lite server
ALLOWED_DOMAIN = "google.com"
# Address the TP-Lite server returns for ALLOWED_DOMAIN
ALLOWED_DOMAIN_IP = "142.250.179.206"

NON_PLAINTEXT_DNS_PORTS = ["443", "853"]

# Standard (non-blocking) DNS server. Unlike the TP-Lite server it resolves
# blocked-malware.com instead of returning NXDOMAIN.
STANDARD_DNS_IP = config.LAN_ADDR_MAP[ConnectionTag.DOCKER_DNS_SERVER_1]["primary"]
# Address the standrd dns-server returns for blocked-malware.com
WHITELIST_RESOLVED_IP = "123.123.123.123"
# TTL the standard dns-server attaches to its blocked-malware.com answer.
# Must match the explicit ttl configured in nat-lab/bin/dns-server.
WHITELIST_RESOLVED_TTL = 3600

CALLBACK_INTERVAL_S = 1  # Use short interval for all tests

# Number of on/off cycles in the repeated enable/disable stress test
NUM_TOGGLE_ITERATIONS = 10


def _features_with_firewall():
    features = default_features()
    features.firewall = FeatureFirewall(
        neptun_reset_conns=False,
        boringtun_reset_conns=False,
        exclude_private_ip_range=None,
        outgoing_blacklist=[],
    )
    return features


def _tp_lite_config(
    dns_server_ips: Optional[list[str]] = None,
    force_plaintext_dns: Optional[bool] = None,
):
    return TpLiteStatsOptions(
        dns_server_ips=(
            dns_server_ips if dns_server_ips is not None else [TP_LITE_DNS_IP]
        ),
        callback_interval_s=CALLBACK_INTERVAL_S,
        blocked_domains_buffer_size=None,
        cache_size=None,
        max_open_requests=None,
        force_plaintext_dns=force_plaintext_dns,
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


async def _query_blocked_expect_failure(connection: Connection) -> None:
    """A blocked NXDOMAIN query against the TP-Lite server fails at the DNS level."""
    with pytest.raises(Exception):
        await query_dns(
            connection, BLOCKED_NXDOMAIN, dns_server=TP_LITE_DNS_IP, options=["-type=a"]
        )


async def _dig_magic_dns(connection: Connection, domain: str) -> tuple[str, str]:
    """Resolve `domain` through MagicDNS with dig and return (stdout, stderr).

    Unlike nslookup, dig prints the TTL of the answer, which lets the caller
    tell a freshly fetched answer apart from one replayed out of the resolver
    cache. `+noall +answer` reduces the output to just the answer section, so
    the TTL is the second whitespace-separated field, same as in
    test_dns.py::test_dns_ttl_value.
    """
    process = await connection.create_process([
        "dig",
        "+noall",
        "+nocmd",
        "+answer",
        "+timeout=5",
        domain,
        f"@{config.LIBTELIO_DNS_IPV4}",
    ]).execute()
    return process.get_stdout(), process.get_stderr()


def _parse_dig_a_answer(dig_stdout: str) -> tuple[Optional[int], Optional[str]]:
    """Extract (ttl, address) from the first A record of a `dig +noall +answer`
    output, or (None, None) when there is no A record (e.g. NXDOMAIN)."""
    for line in dig_stdout.splitlines():
        fields = line.split()
        # <name> <ttl> <class> <type> <rdata>
        if len(fields) >= 5 and fields[3] == "A":
            return int(fields[1]), fields[4]
    return None, None


async def _assert_served_from_cache(
    client, domain: str, log_offset: int, expected: bool
) -> None:
    """Assert whether the most recent lookup of `domain` was answered from the
    MagicDNS (hickory) resolver cache rather than by querying upstream.

    Only log lines produced after `log_offset` are considered, so the caller can
    scope the check to a single query.

    Two markers straddle the cache branch in hickory's CachingClient::inner_lookup
    (crates/resolver/src/caching_client.rs:180):

        telio_dns::forward:220  "forwarding lookup: <domain> <type>"
            -> logged before the cache is consulted, so it appears either way
        hickory_proto::xfer::dns_handle:67  "querying: <domain> <type>"
            -> logged inside DnsHandle::lookup, which is only reached when
               lookup_from_cache() returned None

    So "forwarding lookup" present + "querying" absent means the answer came out
    of the cache and no DNS packet was ever emitted - which also means the
    firewall never had a chance to act on the query.
    """
    logs = (await client.log.get())[log_offset:]
    forwarded = f"forwarding lookup: {domain}" in logs
    queried_upstream = f"querying: {domain}" in logs

    assert forwarded, (
        f"expected a 'forwarding lookup: {domain}' entry, meaning the request"
        " reached the MagicDNS forward zone; found none, so the test did not"
        " exercise the resolver at all"
    )

    if expected:
        assert not queried_upstream, (
            f"expected '{domain}' to be answered from the resolver cache, but"
            " an upstream query was sent ('querying:' present in the log)"
        )
    else:
        assert queried_upstream, (
            f"expected '{domain}' to be resolved upstream, but no 'querying:'"
            " entry was logged, so it was answered from the resolver cache"
        )


async def _bg_tp_lite_traffic(connection: Connection) -> None:
    """Keep DNS lookups flowing to the TP-Lite server so statistics are
    continuously being reported while we toggle the feature on and off.
    Mixes allowed and blocked lookups so both kinds of results are produced."""
    domains = [ALLOWED_DOMAIN, BLOCKED_NXDOMAIN, BLOCKED_NULL_IP]
    i = 0
    while True:
        host = domains[i % len(domains)]
        try:
            await query_dns(
                connection,
                host,
                dns_server=TP_LITE_DNS_IP,
                options=["-type=a", "-timeout=1"],
                quiet=True,
            )
        except ProcessExecError as e:
            assert f"server can't find {host}: NXDOMAIN" in e.stdout
        await asyncio.sleep(0.5)
        i += 1


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
    @pytest.mark.libfirewall
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

        await client.tp_lite.enable_stats_collection(_tp_lite_config())

        await query_dns(
            connection, ALLOWED_DOMAIN, dns_server=TP_LITE_DNS_IP, options=["-type=a"]
        )

        # Query blocked domain
        await _query_blocked_expect_failure(connection)
        # Query same blocked domain again to trigger a cache hit
        await _query_blocked_expect_failure(connection)
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
        (num_calls, domains, metrics) = await client.tp_lite.get_stats()

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

        await client.tp_lite.disable_stats_collection()

        # Make query after disabling, should not trigger callback
        await _query_blocked_expect_failure(connection)

        await _trigger_stats_collection(connection)
        (num_calls, _, _) = await client.tp_lite.get_stats()
        assert num_calls == 0

    @pytest.mark.parametrize(
        "alpha_setup_params",
        [pytest.param(_alpha_setup_params_with_firewall())],
    )
    @pytest.mark.asyncio
    @pytest.mark.libfirewall
    async def test_tp_lite_force_plaintext_dns(
        self,
        alpha_setup_params: SetupParameters,  # pylint: disable=unused-argument
        env: Environment,
    ) -> None:
        """With force_plaintext_dns enabled, the firewall blocks traffic to the
        configured DNS server on any port other than 53 (e.g. DoT/DoH), so only
        plaintext DNS — which the TP-Lite stats collector can inspect — gets through.

        Steps:
            1. Connect to VPN.
            2. Enable stats collection with force_plaintext_dns=False, query the
               configured DNS server on the non-plaintext ports and verify they
               are allowed through.
            3. Enable stats collection with force_plaintext_dns=True.
            4. Query the configured DNS server on the non-plaintext ports and
               verify they are now blocked, while a different, non-configured DNS
               server on the same ports is still allowed - only the configured
               server is restricted.
            5. Query a blocked domain over plaintext (port 53), trigger a stats
               flush, and verify it is reported exactly once.
            6. Re-enable with force_plaintext_dns=False and verify the non-plaintext
               ports to the configured server work again.
            7. Disable stats collection.
        """
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

        await client.tp_lite.enable_stats_collection(_tp_lite_config())
        for port in NON_PLAINTEXT_DNS_PORTS:
            await query_dns_port(
                connection, port, ALLOWED_DOMAIN, TP_LITE_DNS_IP, [ALLOWED_DOMAIN_IP]
            )

        await client.tp_lite.enable_stats_collection(
            _tp_lite_config(force_plaintext_dns=True)
        )

        # LLT-7452: This sleep is added as a regression test in order to validate that
        # the configuration set by enable_stats_collection is not cleared by the
        # firewall consilidation. Consolidation runs every 5 seconds.
        await asyncio.sleep(10)

        for port in NON_PLAINTEXT_DNS_PORTS:
            with pytest.raises(ProcessExecError):
                await query_dns_port(connection, port, ALLOWED_DOMAIN, TP_LITE_DNS_IP)
            await query_dns_port(
                connection, port, ALLOWED_DOMAIN, STANDARD_DNS_IP, [ALLOWED_DOMAIN_IP]
            )

        await _query_blocked_expect_failure(connection)
        await _trigger_stats_collection(connection)
        (num_calls, domains, metrics) = await client.tp_lite.get_stats()
        assert num_calls == 1
        assert BLOCKED_NXDOMAIN in [d.domain_name for d in domains]
        assert metrics.num_requests == 1
        assert metrics.num_responses == 1

        await client.tp_lite.enable_stats_collection(
            _tp_lite_config(force_plaintext_dns=False)
        )
        for port in NON_PLAINTEXT_DNS_PORTS:
            await query_dns_port(
                connection, port, ALLOWED_DOMAIN, TP_LITE_DNS_IP, [ALLOWED_DOMAIN_IP]
            )

        await client.tp_lite.disable_stats_collection()

    @pytest.mark.parametrize(
        "alpha_setup_params",
        [pytest.param(_alpha_setup_params_with_firewall())],
    )
    @pytest.mark.asyncio
    @pytest.mark.libfirewall
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
            await client.tp_lite.enable_stats_collection(_tp_lite_config())

            await _trigger_stats_collection(connection)
            (num_calls, _, _) = await client.tp_lite.get_stats()
            assert num_calls == 0

            await _query_blocked_expect_failure(connection)

            await _trigger_stats_collection(connection)
            (num_calls, domains, metrics) = await client.tp_lite.get_stats()

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
    @pytest.mark.libfirewall
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
            await client.tp_lite.enable_stats_collection(
                _tp_lite_config(dns_server_ips=[])
            )

    @pytest.mark.parametrize(
        "alpha_setup_params",
        [pytest.param(_alpha_setup_params_default())],
    )
    @pytest.mark.asyncio
    @pytest.mark.libfirewall
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
            await client.tp_lite.enable_stats_collection(_tp_lite_config())

    @pytest.mark.parametrize(
        "alpha_setup_params",
        [pytest.param(_alpha_setup_params_with_firewall())],
    )
    @pytest.mark.asyncio
    @pytest.mark.libfirewall
    async def test_tp_lite_stats_repeated_enable_disable_under_traffic(
        self,
        alpha_setup_params: SetupParameters,  # pylint: disable=unused-argument
        env: Environment,
    ) -> None:
        """Repeatedly turn TP-Lite statistics on and off while it is actively
        reporting domains, and check the library stays healthy.

        This mimics a user rapidly toggling the Threat Protection setting (and
        the app re-applying it on top of itself) while protection is busy. The
        goal is to catch crashes or corrupted data caused by switching the
        feature on and off while it is under load.

        Steps:
            1. Connect to VPN
            2. Start background DNS lookups
            3. Repeat 10 times:
                a. Turn stats on
                b. Read the stats while reporting is in progress.
                c. Turn stats on again without turning it off first
                d. Turn stats off
                e. Read the stats after turning off (must still return).
            4. Stop the background traffic and wait for it to finish.
            5. Confirm the feature still works: turn it on, look up a blocked
               domain, and verify it is reported exactly once, then turn it off.
        """
        [alpha] = env.nodes
        [client] = env.clients
        [connection] = [c.connection for c in env.connections]

        await connect_vpn(
            connection, None, client, alpha.ip_addresses[0], config.WG_SERVER
        )

        async with asyncio_util.run_async_context(_bg_tp_lite_traffic(connection)):
            for iteration in range(NUM_TOGGLE_ITERATIONS):
                log.info("TP-Lite enable/disable iteration %d", iteration + 1)
                await client.tp_lite.enable_stats_collection(_tp_lite_config())
                await asyncio.sleep(CALLBACK_INTERVAL_S + 0.5)
                await client.tp_lite.get_stats()

                await client.tp_lite.enable_stats_collection(_tp_lite_config())
                await asyncio.sleep(CALLBACK_INTERVAL_S + 0.5)

                await client.tp_lite.disable_stats_collection()
                await client.tp_lite.get_stats()

        await client.tp_lite.enable_stats_collection(_tp_lite_config())
        await _query_blocked_expect_failure(connection)
        await _trigger_stats_collection(connection)
        (num_calls, domains, _) = await client.tp_lite.get_stats()
        assert num_calls == 1
        assert BLOCKED_NXDOMAIN in [d.domain_name for d in domains]
        await client.tp_lite.disable_stats_collection()

    @pytest.mark.parametrize(
        "alpha_setup_params",
        [pytest.param(_alpha_setup_params_with_firewall())],
    )
    @pytest.mark.asyncio
    @pytest.mark.libfirewall
    async def test_tp_lite_stats_survives_vpn_disconnect_reconnect(
        self,
        alpha_setup_params: SetupParameters,  # pylint: disable=unused-argument
        env: Environment,
    ) -> None:
        """Verify TP-Lite stats collection is independent of the VPN session: it
        pauses on disconnect and resumes on reconnect without tearing down or
        crashing.

        Steps:
            1. Connect to VPN and enable stats collection.
            2. While connected, query a blocked domain and confirm it is collected
               exactly once.
            3. Disconnect the VPN while stats stay enabled.
            4. Query the blocked domain while disconnected
            5. Reconnect the VPN.
            6. Query the blocked domain again and confirm collection resumed:
               exactly one call, the blocked domain is reported, and only the
               single post-reconnect request is counted (proving the disconnected
               query was not collected).
            7. Disable stats collection.
        """
        [alpha] = env.nodes
        [client] = env.clients
        [connection] = [c.connection for c in env.connections]

        await connect_vpn(
            connection, None, client, alpha.ip_addresses[0], config.WG_SERVER
        )
        await client.tp_lite.enable_stats_collection(_tp_lite_config())

        await _query_blocked_expect_failure(connection)
        await _trigger_stats_collection(connection)
        (num_calls, domains, _) = await client.tp_lite.get_stats()
        assert num_calls == 1
        assert BLOCKED_NXDOMAIN in [d.domain_name for d in domains]

        await client.vpn.disconnect(str(config.WG_SERVER["public_key"]))

        await _query_blocked_expect_failure(connection)

        await connect_vpn(
            connection, None, client, alpha.ip_addresses[0], config.WG_SERVER
        )
        await _query_blocked_expect_failure(connection)
        await _trigger_stats_collection(connection)
        (num_calls, domains, metrics) = await client.tp_lite.get_stats()
        assert num_calls == 1
        assert BLOCKED_NXDOMAIN in [d.domain_name for d in domains]
        assert metrics.num_requests == 1

        await client.tp_lite.disable_stats_collection()

    @pytest.mark.parametrize(
        "alpha_setup_params",
        [pytest.param(_alpha_setup_params_with_firewall())],
    )
    @pytest.mark.asyncio
    @pytest.mark.libfirewall
    async def test_tp_lite_stats_enable_before_vpn_connect(
        self,
        alpha_setup_params: SetupParameters,  # pylint: disable=unused-argument
        env: Environment,
    ) -> None:
        """Verify stats collection can be enabled while the VPN is disconnected and
        starts collecting once the VPN connects.

        Steps:
            1. Without connecting the VPN, enable stats collection; the call must
               succeed (collection is independent of the VPN connection).
            2. Query a blocked domain while disconnected.
            3. Connect the VPN.
            4. Query the blocked domain and confirm collection has now started:
               exactly one call, the blocked domain reported, only the single
               post-connect request counted.
            5. Disable stats while connected, then disconnect.
        """
        [alpha] = env.nodes
        [client] = env.clients
        [connection] = [c.connection for c in env.connections]

        await client.tp_lite.enable_stats_collection(_tp_lite_config())

        await _query_blocked_expect_failure(connection)

        await connect_vpn(
            connection, None, client, alpha.ip_addresses[0], config.WG_SERVER
        )

        await _query_blocked_expect_failure(connection)
        await _trigger_stats_collection(connection)
        (num_calls, domains, metrics) = await client.tp_lite.get_stats()
        assert num_calls == 1
        assert BLOCKED_NXDOMAIN in [d.domain_name for d in domains]
        assert metrics.num_requests == 1

        await client.tp_lite.disable_stats_collection()
        await client.vpn.disconnect(str(config.WG_SERVER["public_key"]))

    @pytest.mark.parametrize(
        "alpha_setup_params",
        [pytest.param(_alpha_setup_params_with_firewall())],
    )
    @pytest.mark.asyncio
    @pytest.mark.libfirewall
    async def test_tp_lite_stats_pending_survive_vpn_disconnect(
        self,
        alpha_setup_params: SetupParameters,  # pylint: disable=unused-argument
        env: Environment,
    ) -> None:
        """Verify stats collected but not yet flushed survive a VPN disconnect and
        are delivered after reconnect (no data loss).

        Steps:
            1. Connect the VPN and enable stats collection.
            2. Query a blocked domain so it is buffered, but do NOT trigger stats collection.
            3. Disconnect the VPN, while the data is still pending.
            4. Wait past the callback interval during the outage so the flush
               threshold elapses while disconnected.
            5. Reconnect the VPN.
            6. Trigger a flush and confirm the pre-disconnect blocked domain is
               delivered: exactly one call, the domain reported, and only the
               single pre-disconnect request counted (no data lost or duplicated).
            7. Disable stats collection.
        """
        [alpha] = env.nodes
        [client] = env.clients
        [connection] = [c.connection for c in env.connections]

        await connect_vpn(
            connection, None, client, alpha.ip_addresses[0], config.WG_SERVER
        )
        await client.tp_lite.enable_stats_collection(_tp_lite_config())

        await _query_blocked_expect_failure(connection)

        await client.vpn.disconnect(str(config.WG_SERVER["public_key"]))

        await asyncio.sleep(CALLBACK_INTERVAL_S + 1)

        await connect_vpn(
            connection, None, client, alpha.ip_addresses[0], config.WG_SERVER
        )

        await _trigger_stats_collection(connection)
        (num_calls, domains, metrics) = await client.tp_lite.get_stats()
        assert num_calls == 1
        assert BLOCKED_NXDOMAIN in [d.domain_name for d in domains]
        assert metrics.num_requests == 1

        await client.tp_lite.disable_stats_collection()

    @pytest.mark.parametrize(
        "alpha_setup_params",
        [pytest.param(_alpha_setup_params_with_firewall())],
    )
    @pytest.mark.asyncio
    @pytest.mark.libfirewall
    async def test_tp_lite_stats_with_magic_dns(
        self,
        alpha_setup_params: SetupParameters,  # pylint: disable=unused-argument
        env: Environment,
    ) -> None:
        """Verify that MagicDNS doesn't interfere with stats collection.

        Steps:
            1. Connect the VPN, enable MagicDNS and enable stats collection.
            2. Query a blocked domain.
            3. Trigger a flush and confirm that the DNS request and response
               show up in the metrics and blocked domains.
            4. Disable stats collection.
        """

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

        await client.enable_magic_dns([TP_LITE_DNS_IP])

        await client.tp_lite.enable_stats_collection(_tp_lite_config())

        with pytest.raises(Exception):
            await query_dns(
                connection,
                BLOCKED_NXDOMAIN,
                dns_server=config.LIBTELIO_DNS_IPV4,
                options=["-type=a"],
            )

        await _trigger_stats_collection(connection)
        (num_calls, domains, metrics) = await client.tp_lite.get_stats()

        blocked_domain_names = [d.domain_name for d in domains]

        assert num_calls == 1
        assert metrics.num_requests == 1
        assert metrics.num_responses == 1
        assert metrics.num_cache_hits == 0

        assert BLOCKED_NXDOMAIN in blocked_domain_names
        nxdomain_entry = next(d for d in domains if d.domain_name == BLOCKED_NXDOMAIN)
        assert "malware" in nxdomain_entry.category.lower()

        await client.tp_lite.disable_stats_collection()


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
        await _query_blocked_expect_failure(connection)

        # Configure the whitelist and the DNS redirect at runtime, which
        # reconfigures the firewall.
        await client.tp_lite.set_domain_whitelist(
            [BLOCKED_NXDOMAIN],
            [
                DnsRedirect(
                    blocking=f"{TP_LITE_DNS_IP}:53",
                    standard=f"{STANDARD_DNS_IP}:53",
                )
            ],
        )

        # LLT-7452: This sleep is added as a regression test in order to validate that
        # the configuration set by set_domain_whitelist is not cleared by the
        # firewall consilidation. Consolidation runs every 5 seconds.
        await asyncio.sleep(10)

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
    async def test_dns_whitelisting_stale_cache_after_reblock(
        self,
        alpha_setup_params: SetupParameters,  # pylint: disable=unused-argument
        env: Environment,
    ) -> None:
        """LLT-7558: re-blocking a previously whitelisted domain has no effect
        while the MagicDNS resolver still has the whitelisted answer cached.

        Unlike test_dns_whitelisting_redirects_blocked_domain, which queries the
        TP-Lite server directly, this test resolves through MagicDNS. That puts
        hickory's DnsLru in front of the firewall, and the firewall can only act
        on queries that actually reach it - a cache hit is answered before any
        packet is emitted (crates/resolver/src/caching_client.rs:180).

        Steps:
            1. Connect the VPN and enable MagicDNS pointed at the TP-Lite server.
            2. Whitelist the domain. The firewall DNATs the query to the standard
               DNS server, which answers with a long-lived (TTL 3600) record that
               the resolver caches.
            3. Clear the whitelist. The firewall stops redirecting, but the
               cached answer keeps the domain resolvable, so it stays reachable
               even though it is supposed to be blocked again.

        NOTE: this test asserts the *current, buggy* behaviour so the defect is
        pinned. See the assertions in step 3 for what to change once it is fixed.

        NOTE: there is deliberately no "confirm it is blocked first" query before
        step 2. The nat-lab TP-Lite server answers NXDOMAIN with an SOA carrying
        ttl=300 and minimum=300 (nat-lab/bin/tp-lite-dns-server), so hickory
        derives a negative_ttl of min(ttl, minimum) = 300
        (crates/proto/src/xfer/dns_response.rs:227) and caches the NXDOMAIN for
        five minutes. Such a query would poison the cache and make step 2 fail,
        because the whitelisted lookup would be served from that negative entry
        instead of reaching the firewall. The production TP-Lite server sends
        minimum=0 instead, so its NXDOMAIN is never retained - which is exactly
        why block -> unblock works in the field while unblock -> re-block does
        not. test_dns_whitelisting_redirects_blocked_domain already covers the
        blocked-first direction.

        NOTE: this depends on FeatureDns::use_raw_forwarder being left at its
        default of false (crates/telio-dns/src/dns.rs:86), which selects the
        hickory forwarder. The alternative RawForwarder has no cache and would
        not reproduce this.
        """

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

        # Route client DNS through MagicDNS, which forwards to the TP-Lite server.
        # This is what puts the resolver cache in front of the firewall.
        await client.enable_magic_dns([TP_LITE_DNS_IP])

        redirects = [
            DnsRedirect(
                blocking=f"{TP_LITE_DNS_IP}:53",
                standard=f"{STANDARD_DNS_IP}:53",
            )
        ]

        # Step 2: whitelist the domain. The firewall now DNATs the query to the
        # standard DNS server, which resolves it - and the resolver caches that
        # answer for its full TTL.
        #
        # This is the first lookup of BLOCKED_NXDOMAIN in the test, on purpose:
        # see the note in the docstring about the nat-lab TP-Lite server caching
        # its NXDOMAIN for 300s.
        await client.tp_lite.set_domain_whitelist([BLOCKED_NXDOMAIN], redirects)
        stdout, stderr = await _dig_magic_dns(connection, BLOCKED_NXDOMAIN)
        ttl, address = _parse_dig_a_answer(stdout)
        assert address == WHITELIST_RESOLVED_IP, (
            f"expected {BLOCKED_NXDOMAIN} to be redirected to the standard DNS"
            f" server after whitelisting, got {address}. An empty answer here"
            " usually means a cached NXDOMAIN was served instead of the query"
            " reaching the firewall - check that nothing looked this domain up"
            " earlier in the test (see the docstring)."
            f"\ndig stdout:\n{stdout}\ndig stderr:\n{stderr}"
        )
        # A fresh upstream answer carries the TTL configured in nat-lab/bin/dns-server.
        # If this ever fails, the record is being served with a different (likely 0)
        # TTL, the resolver would not retain it, and the rest of the test would pass
        # for the wrong reason.
        assert ttl == WHITELIST_RESOLVED_TTL, (
            f"expected a freshly resolved answer with TTL {WHITELIST_RESOLVED_TTL},"
            f" got {ttl}; the answer must be cacheable for this test to be"
            f" meaningful\ndig stdout:\n{stdout}\ndig stderr:\n{stderr}"
        )

        # Step 3: clear the whitelist. The firewall drops the DNAT rule, so a
        # query that reaches it would be blocked again.
        await client.tp_lite.set_domain_whitelist([], redirects)

        # Give the cached entry a moment to visibly age. DnsLru reports the
        # remaining lifetime truncated to whole seconds, so this makes the
        # "TTL went down" assertion below unambiguous rather than relying on
        # sub-second truncation.
        await asyncio.sleep(2)

        # Only look at log output produced by the query below.
        log_offset = len(await client.log.get())
        stdout, stderr = await _dig_magic_dns(connection, BLOCKED_NXDOMAIN)
        ttl, address = _parse_dig_a_answer(stdout)

        # CURRENT (BUGGY) BEHAVIOUR - LLT-7558.
        # The whitelist is empty, so libfirewall no longer DNATs this query and
        # the domain should be NXDOMAIN again. Instead MagicDNS still holds the
        # positive answer cached from step 2 and returns it without emitting a
        # packet, so the firewall never sees the query.
        # WHEN FIXED: assert `address is None` here, and flip the
        # _assert_served_from_cache call below to expected=False.
        assert address == WHITELIST_RESOLVED_IP, (
            f"expected the stale cached answer {WHITELIST_RESOLVED_IP} for"
            f" {BLOCKED_NXDOMAIN} after re-blocking (LLT-7558), got"
            f" {address}\ndig stdout:\n{stdout}\ndig stderr:\n{stderr}"
        )

        # A decremented TTL is the signature of a cache replay: DnsLru::get
        # rewrites the record TTL to the entry's remaining lifetime
        # (crates/resolver/src/dns_lru.rs:46). A fresh upstream answer would
        # carry the full WHITELIST_RESOLVED_TTL again.
        assert ttl is not None and ttl < WHITELIST_RESOLVED_TTL, (
            f"expected a decremented TTL indicating a cached answer, got {ttl}"
            f"\ndig stdout:\n{stdout}\ndig stderr:\n{stderr}"
        )

        # And the direct evidence: no upstream query was sent for this lookup.
        await _assert_served_from_cache(
            client, BLOCKED_NXDOMAIN, log_offset, expected=True
        )

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
    async def test_dns_whitelisting_reblock_is_effective(
        self,
        alpha_setup_params: SetupParameters,  # pylint: disable=unused-argument
        env: Environment,
    ) -> None:
        """LLT-7558: clearing the TP-Lite whitelist must make the domain blocked
        again, even if it was resolved - and cached by MagicDNS - while it was
        whitelisted.

        *** THIS TEST IS EXPECTED TO FAIL UNTIL LLT-7558 IS FIXED. ***
        It asserts the correct, intended behaviour. Its counterpart,
        test_dns_whitelisting_stale_cache_after_reblock, pins the current broken
        behaviour; when the fix lands this test turns green and that one must be
        updated.

        The fix must invalidate the MagicDNS resolver cache when the whitelist
        changes: the firewall only ever sees queries that miss the cache
        (crates/resolver/src/caching_client.rs:180), so as long as a whitelisted
        answer stays cached the domain remains reachable no matter what the
        firewall chain says.

        Steps:
            1. Connect the VPN and enable MagicDNS pointed at the TP-Lite server.
            2. Whitelist the domain. The firewall DNATs the query to the standard
               DNS server, which answers with a long-lived (TTL 3600) record that
               the resolver caches.
            3. Clear the whitelist and query again. The domain must be blocked,
               and the query must actually reach the firewall rather than being
               answered from the cache.

        NOTE: there is deliberately no "confirm it is blocked first" query before
        step 2. The nat-lab TP-Lite server answers NXDOMAIN with an SOA carrying
        ttl=300 and minimum=300 (nat-lab/bin/tp-lite-dns-server), so hickory
        derives a negative_ttl of min(ttl, minimum) = 300
        (crates/proto/src/xfer/dns_response.rs:227) and caches the NXDOMAIN for
        five minutes. Such a query would poison the cache and make step 2 fail,
        because the whitelisted lookup would be served from that negative entry
        instead of reaching the firewall.

        NOTE: this depends on FeatureDns::use_raw_forwarder being left at its
        default of false (crates/telio-dns/src/dns.rs:86), which selects the
        hickory forwarder. The alternative RawForwarder has no cache, so the
        behaviour asserted here would already hold.
        """

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

        # Route client DNS through MagicDNS, which forwards to the TP-Lite server.
        # This is what puts the resolver cache in front of the firewall.
        await client.enable_magic_dns([TP_LITE_DNS_IP])

        redirects = [
            DnsRedirect(
                blocking=f"{TP_LITE_DNS_IP}:53",
                standard=f"{STANDARD_DNS_IP}:53",
            )
        ]

        # Step 2: whitelist the domain so the firewall DNATs the query to the
        # standard DNS server, and the resolver caches the answer it returns.
        #
        # This is the first lookup of BLOCKED_NXDOMAIN in the test, on purpose:
        # see the note in the docstring about the nat-lab TP-Lite server caching
        # its NXDOMAIN for 300s.
        await client.tp_lite.set_domain_whitelist([BLOCKED_NXDOMAIN], redirects)
        stdout, stderr = await _dig_magic_dns(connection, BLOCKED_NXDOMAIN)
        ttl, address = _parse_dig_a_answer(stdout)
        assert address == WHITELIST_RESOLVED_IP, (
            f"expected {BLOCKED_NXDOMAIN} to be redirected to the standard DNS"
            f" server after whitelisting, got {address}. An empty answer here"
            " usually means a cached NXDOMAIN was served instead of the query"
            " reaching the firewall - check that nothing looked this domain up"
            " earlier in the test (see the docstring)."
            f"\ndig stdout:\n{stdout}\ndig stderr:\n{stderr}"
        )
        # Guard the precondition: the answer has to be cacheable for this test to
        # be meaningful. If it is served with a different (likely 0) TTL the
        # resolver would not retain it and the assertions below would hold
        # trivially, for the wrong reason.
        assert ttl == WHITELIST_RESOLVED_TTL, (
            f"expected a freshly resolved answer with TTL {WHITELIST_RESOLVED_TTL},"
            f" got {ttl}; the answer must be cacheable for this test to be"
            f" meaningful\ndig stdout:\n{stdout}\ndig stderr:\n{stderr}"
        )

        # Step 3: clear the whitelist. The firewall drops the DNAT rule, so the
        # domain must be blocked again.
        await client.tp_lite.set_domain_whitelist([], redirects)

        # Match the timing of the counterpart test so both observe the cache in
        # the same state.
        await asyncio.sleep(2)

        # Only look at log output produced by the query below.
        log_offset = len(await client.log.get())
        stdout, stderr = await _dig_magic_dns(connection, BLOCKED_NXDOMAIN)
        _, address = _parse_dig_a_answer(stdout)

        # EXPECTED BEHAVIOUR - currently fails, see LLT-7558.
        # With an empty whitelist the query is no longer DNATed, so it reaches
        # the blocking TP-Lite server and comes back NXDOMAIN, i.e. no A record.
        assert address is None, (
            f"expected {BLOCKED_NXDOMAIN} to be blocked again after the whitelist"
            f" was cleared, but it resolved to {address}. The MagicDNS resolver"
            " is still serving the answer cached while the domain was"
            " whitelisted (LLT-7558)."
            f"\ndig stdout:\n{stdout}\ndig stderr:\n{stderr}"
        )

        # Being blocked is not enough on its own - the query also has to have
        # reached the firewall. Without this the test could pass for the wrong
        # reason, e.g. if the entry had simply been evicted from the 32-entry
        # LRU rather than deliberately invalidated.
        await _assert_served_from_cache(
            client, BLOCKED_NXDOMAIN, log_offset, expected=False
        )
