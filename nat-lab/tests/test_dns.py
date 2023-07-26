from utils import process
from contextlib import AsyncExitStack
from mesh_api import API
from telio import AdapterType, PathType
import asyncio
import config
import pytest
import telio
import utils.testing as testing
import re
from utils.connection_tracker import (
    ConnectionLimits,
    generate_connection_tracker_config,
)
from utils import ConnectionTag, new_connection_with_conn_tracker, new_connection_by_tag

DNS_SERVER_ADDRESS = config.LIBTELIO_DNS_IP


@pytest.mark.asyncio
async def test_dns() -> None:
    async with AsyncExitStack() as exit_stack:
        api = API()

        (alpha, beta) = api.default_config_two_nodes()

        alpha.set_peer_firewall_settings(beta.id)
        beta.set_peer_firewall_settings(alpha.id)

        (connection_alpha, alpha_conn_tracker) = await exit_stack.enter_async_context(
            new_connection_with_conn_tracker(
                ConnectionTag.DOCKER_CONE_CLIENT_1,
                generate_connection_tracker_config(
                    ConnectionTag.DOCKER_CONE_CLIENT_1,
                    derp_1_limits=ConnectionLimits(1, 1),
                ),
            )
        )
        (connection_beta, beta_conn_tracker) = await exit_stack.enter_async_context(
            new_connection_with_conn_tracker(
                ConnectionTag.DOCKER_CONE_CLIENT_2,
                generate_connection_tracker_config(
                    ConnectionTag.DOCKER_CONE_CLIENT_2,
                    derp_1_limits=ConnectionLimits(1, 1),
                ),
            )
        )

        client_alpha = await exit_stack.enter_async_context(
            telio.Client(connection_alpha, alpha,).run_meshnet(
                api.get_meshmap(alpha.id),
            )
        )

        client_beta = await exit_stack.enter_async_context(
            telio.Client(connection_beta, beta,).run_meshnet(
                api.get_meshmap(beta.id),
            )
        )

        await testing.wait_long(
            asyncio.gather(
                client_alpha.wait_for_any_derp_state([telio.State.Connected]),
                client_beta.wait_for_any_derp_state([telio.State.Connected]),
            )
        )

        await testing.wait_long(
            asyncio.gather(
                alpha_conn_tracker.wait_for_event("derp_1"),
                beta_conn_tracker.wait_for_event("derp_1"),
            )
        )

        await testing.wait_long(
            asyncio.gather(
                client_alpha.handshake(beta.public_key),
                client_beta.handshake(alpha.public_key),
            )
        )

        # These calls should timeout without returning anything, but cache the peer addresses
        with pytest.raises(asyncio.TimeoutError):
            await testing.wait_long(
                connection_alpha.create_process(
                    ["nslookup", "google.com", DNS_SERVER_ADDRESS]
                ).execute()
            )

        with pytest.raises(asyncio.TimeoutError):
            await testing.wait_long(
                connection_beta.create_process(
                    ["nslookup", "google.com", DNS_SERVER_ADDRESS]
                ).execute()
            )

        await client_alpha.enable_magic_dns(["1.1.1.1"])
        await client_beta.enable_magic_dns(["1.1.1.1"])

        # If everything went correctly, these calls should not timeout
        await testing.wait_long(
            connection_alpha.create_process(
                ["nslookup", "google.com", DNS_SERVER_ADDRESS]
            ).execute(),
        )
        await testing.wait_long(
            connection_beta.create_process(
                ["nslookup", "google.com", DNS_SERVER_ADDRESS]
            ).execute(),
        )

        # If the previous calls didn't fail, we can assume that the resolver is running so no need to wait for the timeout and test the validity of the response
        alpha_response = await testing.wait_long(
            connection_alpha.create_process(
                ["nslookup", "beta.nord", DNS_SERVER_ADDRESS]
            ).execute()
        )
        assert beta.ip_addresses[0] in alpha_response.get_stdout()

        beta_response = await testing.wait_long(
            connection_beta.create_process(
                ["nslookup", "alpha.nord", DNS_SERVER_ADDRESS]
            ).execute()
        )
        assert alpha.ip_addresses[0] in beta_response.get_stdout()

        # Now we disable magic dns
        await client_alpha.disable_magic_dns()
        await client_beta.disable_magic_dns()

        # And as a result these calls should timeout again
        with pytest.raises(asyncio.TimeoutError):
            await testing.wait_long(
                connection_alpha.create_process(
                    ["nslookup", "google.com", DNS_SERVER_ADDRESS]
                ).execute(),
            )
        with pytest.raises(asyncio.TimeoutError):
            await testing.wait_long(
                connection_beta.create_process(
                    ["nslookup", "google.com", DNS_SERVER_ADDRESS]
                ).execute(),
            )

        assert alpha_conn_tracker.get_out_of_limits() is None
        assert beta_conn_tracker.get_out_of_limits() is None


@pytest.mark.asyncio
async def test_dns_port() -> None:
    async with AsyncExitStack() as exit_stack:
        api = API()

        (alpha, beta) = api.default_config_two_nodes()

        alpha.set_peer_firewall_settings(beta.id)
        beta.set_peer_firewall_settings(alpha.id)

        (connection_alpha, alpha_conn_tracker) = await exit_stack.enter_async_context(
            new_connection_with_conn_tracker(
                ConnectionTag.DOCKER_CONE_CLIENT_1,
                generate_connection_tracker_config(
                    ConnectionTag.DOCKER_CONE_CLIENT_1,
                    derp_1_limits=ConnectionLimits(1, 1),
                ),
            )
        )
        (connection_beta, beta_conn_tracker) = await exit_stack.enter_async_context(
            new_connection_with_conn_tracker(
                ConnectionTag.DOCKER_CONE_CLIENT_2,
                generate_connection_tracker_config(
                    ConnectionTag.DOCKER_CONE_CLIENT_2,
                    derp_1_limits=ConnectionLimits(1, 1),
                ),
            )
        )

        client_alpha = await exit_stack.enter_async_context(
            telio.Client(connection_alpha, alpha,).run_meshnet(
                api.get_meshmap(alpha.id),
            )
        )

        client_beta = await exit_stack.enter_async_context(
            telio.Client(connection_beta, beta,).run_meshnet(
                api.get_meshmap(beta.id),
            )
        )

        await testing.wait_long(
            asyncio.gather(
                client_alpha.wait_for_any_derp_state([telio.State.Connected]),
                client_beta.wait_for_any_derp_state([telio.State.Connected]),
            )
        )

        await testing.wait_long(
            asyncio.gather(
                alpha_conn_tracker.wait_for_event("derp_1"),
                beta_conn_tracker.wait_for_event("derp_1"),
            )
        )

        await testing.wait_long(
            asyncio.gather(
                client_alpha.handshake(beta.public_key),
                client_beta.handshake(alpha.public_key),
            )
        )

        # These call should timeout without returning anything
        with pytest.raises(asyncio.TimeoutError):
            await testing.wait_normal(
                connection_alpha.create_process(
                    ["dig", "@" + DNS_SERVER_ADDRESS, "-p", "53", "google.com"]
                ).execute()
            )

        await client_alpha.enable_magic_dns(["1.1.1.1"])
        await client_beta.enable_magic_dns(["1.1.1.1"])

        # A DNS request on port 53 should work
        await testing.wait_normal(
            connection_alpha.create_process(
                ["dig", "@" + DNS_SERVER_ADDRESS, "-p", "53", "google.com"]
            ).execute(),
        )

        # A DNS request on a different port should timeout
        with pytest.raises(asyncio.TimeoutError):
            await testing.wait_normal(
                connection_alpha.create_process(
                    ["dig", "@" + DNS_SERVER_ADDRESS, "-p", "54", "google.com"]
                ).execute(),
            )

        # Look for beta on 53 port should work
        alpha_response = await testing.wait_normal(
            connection_alpha.create_process(
                ["dig", "@" + DNS_SERVER_ADDRESS, "-p", "53", "beta.nord"]
            ).execute()
        )
        assert beta.ip_addresses[0] in alpha_response.get_stdout()

        # Look for beta on a different port should timeout
        with pytest.raises(asyncio.TimeoutError):
            await testing.wait_normal(
                connection_alpha.create_process(
                    ["dig", "@" + DNS_SERVER_ADDRESS, "-p", "54", "beta.nord"]
                ).execute(),
            )

        # Disable magic dns
        await client_alpha.disable_magic_dns()
        await client_beta.disable_magic_dns()

        # And as a result these calls should timeout again
        with pytest.raises(asyncio.TimeoutError):
            await testing.wait_normal(
                connection_alpha.create_process(
                    ["dig", "@" + DNS_SERVER_ADDRESS, "-p", "53", "google.com"]
                ).execute(),
            )

        with pytest.raises(asyncio.TimeoutError):
            await testing.wait_normal(
                connection_alpha.create_process(
                    ["dig", "@" + DNS_SERVER_ADDRESS, "-p", "53", "beta.nord"]
                ).execute(),
            )

        assert alpha_conn_tracker.get_out_of_limits() is None
        assert beta_conn_tracker.get_out_of_limits() is None


@pytest.mark.asyncio
async def test_vpn_dns() -> None:
    async with AsyncExitStack() as exit_stack:
        api = API()
        alpha = api.default_config_alpha_node()

        (connection, conn_tracker) = await exit_stack.enter_async_context(
            new_connection_with_conn_tracker(
                ConnectionTag.DOCKER_CONE_CLIENT_1,
                generate_connection_tracker_config(
                    ConnectionTag.DOCKER_CONE_CLIENT_1,
                    vpn_1_limits=ConnectionLimits(1, 1),
                ),
            )
        )

        client_alpha = await exit_stack.enter_async_context(
            telio.Client(
                connection,
                alpha,
            ).run()
        )

        wg_server = config.WG_SERVER

        await testing.wait_long(
            client_alpha.connect_to_vpn(
                wg_server["ipv4"], wg_server["port"], wg_server["public_key"]
            )
        )

        await testing.wait_long(conn_tracker.wait_for_event("vpn_1"))

        await testing.wait_lengthy(
            client_alpha.handshake(wg_server["public_key"], path=PathType.Direct)
        )

        # After we connect to the VPN, enable magic DNS
        await client_alpha.enable_magic_dns(["1.1.1.1"])

        # Test to see if the module is working correctly
        await testing.wait_normal(
            connection.create_process(
                ["nslookup", "google.com", DNS_SERVER_ADDRESS]
            ).execute(),
        )

        # Test if the DNS module preserves CNAME records
        dns_response = await testing.wait_normal(
            connection.create_process(
                ["nslookup", "-q=CNAME", "www.microsoft.com", DNS_SERVER_ADDRESS]
            ).execute(),
        )
        assert "canonical name" in dns_response.get_stdout()

        # Turn off the module and see if it worked
        await client_alpha.disable_magic_dns()

        with pytest.raises(asyncio.TimeoutError):
            await testing.wait_normal(
                connection.create_process(
                    ["nslookup", "google.com", DNS_SERVER_ADDRESS]
                ).execute(),
            )

        # Test interop with meshnet
        await client_alpha.enable_magic_dns(["1.1.1.1"])

        await client_alpha.set_meshmap(api.get_meshmap(alpha.id, derp_servers=[]))

        await testing.wait_normal(
            connection.create_process(
                ["nslookup", "google.com", DNS_SERVER_ADDRESS]
            ).execute(),
        )

        assert conn_tracker.get_out_of_limits() is None


@pytest.mark.asyncio
async def test_dns_after_mesh_off() -> None:
    async with AsyncExitStack() as exit_stack:
        api = API()

        (alpha, beta) = api.default_config_two_nodes()

        alpha.set_peer_firewall_settings(beta.id)
        beta.set_peer_firewall_settings(alpha.id)

        (connection_alpha, alpha_conn_tracker) = await exit_stack.enter_async_context(
            new_connection_with_conn_tracker(
                ConnectionTag.DOCKER_CONE_CLIENT_1,
                generate_connection_tracker_config(
                    ConnectionTag.DOCKER_CONE_CLIENT_1,
                ),
            )
        )

        client_alpha = await exit_stack.enter_async_context(
            telio.Client(connection_alpha, alpha,).run_meshnet(
                api.get_meshmap(alpha.id, derp_servers=[]),
            )
        )

        # These calls should timeout without returning anything, but cache the peer addresses
        with pytest.raises(asyncio.TimeoutError):
            await testing.wait_normal(
                connection_alpha.create_process(
                    ["nslookup", "google.com", DNS_SERVER_ADDRESS]
                ).execute()
            )

        await client_alpha.enable_magic_dns(["1.1.1.1"])

        # If everything went correctly, these calls should not timeout
        await testing.wait_normal(
            connection_alpha.create_process(
                ["nslookup", "google.com", DNS_SERVER_ADDRESS]
            ).execute(),
        )

        # If the previous calls didn't fail, we can assume that the resolver is running so no need to wait for the timeout and test the validity of the response
        alpha_response = await testing.wait_normal(
            connection_alpha.create_process(
                ["nslookup", "beta.nord", DNS_SERVER_ADDRESS]
            ).execute()
        )
        assert beta.ip_addresses[0] in alpha_response.get_stdout()

        # Now we disable magic dns
        await client_alpha.set_mesh_off()

        # If everything went correctly, these calls should not timeout
        await testing.wait_normal(
            connection_alpha.create_process(
                ["nslookup", "google.com", DNS_SERVER_ADDRESS]
            ).execute(),
        )

        # After mesh off, .nord names should not be resolved anymore, therefore nslookup should fail
        try:
            await testing.wait_normal(
                connection_alpha.create_process(
                    ["nslookup", "beta.nord", DNS_SERVER_ADDRESS]
                ).execute(),
            )
        except process.ProcessExecError as e:
            assert "server can't find beta.nord" in e.stdout

        assert alpha_conn_tracker.get_out_of_limits() is None


@pytest.mark.asyncio
@pytest.mark.long
@pytest.mark.timeout(60 * 5 + 60)
@pytest.mark.parametrize(
    "alpha_connection_tag,adapter_type",
    [
        pytest.param(
            ConnectionTag.DOCKER_CONE_CLIENT_1,
            AdapterType.BoringTun,
        ),
    ],
)
async def test_dns_stability(
    alpha_connection_tag: ConnectionTag,
    adapter_type: AdapterType,
) -> None:
    async with AsyncExitStack() as exit_stack:
        api = API()

        (alpha, beta) = api.default_config_two_nodes()
        alpha.set_peer_firewall_settings(beta.id)
        beta.set_peer_firewall_settings(alpha.id)

        (connection_alpha, alpha_conn_tracker) = await exit_stack.enter_async_context(
            new_connection_with_conn_tracker(
                alpha_connection_tag,
                generate_connection_tracker_config(
                    alpha_connection_tag,
                    derp_1_limits=ConnectionLimits(1, 1),
                ),
            )
        )
        (connection_beta, beta_conn_tracker) = await exit_stack.enter_async_context(
            new_connection_with_conn_tracker(
                ConnectionTag.DOCKER_CONE_CLIENT_2,
                generate_connection_tracker_config(
                    ConnectionTag.DOCKER_CONE_CLIENT_2,
                    derp_1_limits=ConnectionLimits(1, 1),
                ),
            )
        )

        client_alpha = await exit_stack.enter_async_context(
            telio.Client(connection_alpha, alpha, adapter_type,).run_meshnet(
                api.get_meshmap(alpha.id),
            )
        )

        client_beta = await exit_stack.enter_async_context(
            telio.Client(connection_beta, beta,).run_meshnet(
                api.get_meshmap(beta.id),
            )
        )

        await testing.wait_long(
            asyncio.gather(
                client_alpha.wait_for_any_derp_state([telio.State.Connected]),
                client_beta.wait_for_any_derp_state([telio.State.Connected]),
            )
        )

        await testing.wait_long(
            asyncio.gather(
                alpha_conn_tracker.wait_for_event("derp_1"),
                beta_conn_tracker.wait_for_event("derp_1"),
            )
        )

        await testing.wait_long(
            asyncio.gather(
                client_alpha.handshake(beta.public_key),
                client_beta.handshake(alpha.public_key),
            )
        )

        await client_alpha.enable_magic_dns(["1.1.1.1"])
        await client_beta.enable_magic_dns(["1.1.1.1"])

        await testing.wait_normal(
            connection_alpha.create_process(
                ["nslookup", "google.com", DNS_SERVER_ADDRESS]
            ).execute(),
        )

        await testing.wait_normal(
            connection_beta.create_process(
                ["nslookup", "google.com", DNS_SERVER_ADDRESS]
            ).execute(),
        )

        alpha_response = await testing.wait_normal(
            connection_alpha.create_process(
                ["nslookup", "beta.nord", DNS_SERVER_ADDRESS]
            ).execute()
        )
        assert beta.ip_addresses[0] in alpha_response.get_stdout()

        beta_response = await testing.wait_normal(
            connection_beta.create_process(
                ["nslookup", "alpha.nord", DNS_SERVER_ADDRESS]
            ).execute()
        )
        assert alpha.ip_addresses[0] in beta_response.get_stdout()

        await asyncio.sleep(60 * 5)

        await testing.wait_normal(
            connection_alpha.create_process(
                ["nslookup", "google.com", DNS_SERVER_ADDRESS]
            ).execute(),
        )

        await testing.wait_normal(
            connection_beta.create_process(
                ["nslookup", "google.com", DNS_SERVER_ADDRESS]
            ).execute(),
        )

        alpha_response = await testing.wait_normal(
            connection_alpha.create_process(
                ["nslookup", "beta.nord", DNS_SERVER_ADDRESS]
            ).execute()
        )
        assert beta.ip_addresses[0] in alpha_response.get_stdout()

        beta_response = await testing.wait_normal(
            connection_beta.create_process(
                ["nslookup", "alpha.nord", DNS_SERVER_ADDRESS]
            ).execute()
        )
        assert alpha.ip_addresses[0] in beta_response.get_stdout()

        assert alpha_conn_tracker.get_out_of_limits() is None
        assert beta_conn_tracker.get_out_of_limits() is None


@pytest.mark.asyncio
async def test_set_meshmap_dns_update() -> None:
    async with AsyncExitStack() as exit_stack:
        api = API()

        alpha = api.default_config_alpha_node()

        (connection_alpha, alpha_conn_tracker) = await exit_stack.enter_async_context(
            new_connection_with_conn_tracker(
                ConnectionTag.DOCKER_CONE_CLIENT_1,
                generate_connection_tracker_config(
                    ConnectionTag.DOCKER_CONE_CLIENT_1,
                ),
            )
        )

        client_alpha = await exit_stack.enter_async_context(
            telio.Client(connection_alpha, alpha,).run_meshnet(
                api.get_meshmap(alpha.id, derp_servers=[]),
            )
        )

        await client_alpha.enable_magic_dns([])

        # We should not be able to resolve beta yet, since it's not registered
        try:
            await testing.wait_normal(
                connection_alpha.create_process(
                    ["nslookup", "beta.nord", DNS_SERVER_ADDRESS]
                ).execute()
            )
        except process.ProcessExecError as e:
            assert "server can't find beta.nord" in e.stdout

        beta = api.default_config_beta_node()

        # Check if setting meshnet updates nord names for dns resolver
        await client_alpha.set_meshmap(api.get_meshmap(alpha.id, derp_servers=[]))

        alpha_response = await testing.wait_normal(
            connection_alpha.create_process(
                ["nslookup", "beta.nord", DNS_SERVER_ADDRESS]
            ).execute(),
        )
        assert beta.ip_addresses[0] in alpha_response.get_stdout()

        assert alpha_conn_tracker.get_out_of_limits() is None


@pytest.mark.asyncio
async def test_dns_update() -> None:
    async with AsyncExitStack() as exit_stack:
        api = API()

        alpha = api.default_config_alpha_node()

        (connection, conn_tracker) = await exit_stack.enter_async_context(
            new_connection_with_conn_tracker(
                ConnectionTag.DOCKER_CONE_CLIENT_1,
                generate_connection_tracker_config(
                    ConnectionTag.DOCKER_CONE_CLIENT_1,
                    vpn_1_limits=ConnectionLimits(1, 1),
                ),
            )
        )

        client_alpha = await exit_stack.enter_async_context(
            telio.Client(
                connection,
                alpha,
            ).run()
        )

        wg_server = config.WG_SERVER

        await testing.wait_long(
            client_alpha.connect_to_vpn(
                wg_server["ipv4"], wg_server["port"], wg_server["public_key"]
            )
        )

        await testing.wait_long(conn_tracker.wait_for_event("vpn_1"))

        await testing.wait_lengthy(
            client_alpha.handshake(wg_server["public_key"], path=PathType.Direct)
        )

        # Don't forward anything yet
        await client_alpha.enable_magic_dns([])

        alpha_response = await testing.wait_normal(
            connection.create_process(
                ["nslookup", "google.com", DNS_SERVER_ADDRESS]
            ).execute(),
        )

        assert "Can't find google.com: No answer" in alpha_response.get_stdout()

        # Update forward dns and check if it works now
        await client_alpha.enable_magic_dns(["1.1.1.1"])

        alpha_response = await testing.wait_normal(
            connection.create_process(
                ["nslookup", "google.com", DNS_SERVER_ADDRESS]
            ).execute(),
        )
        # Check if some address was found
        assert "Name:	google.com\nAddress:" in alpha_response.get_stdout()
        assert conn_tracker.get_out_of_limits() is None


@pytest.mark.asyncio
async def test_dns_duplicate_requests_on_multiple_forward_servers() -> None:
    async with AsyncExitStack() as exit_stack:
        api = API()

        FIRST_DNS_SERVER = "8.8.8.8"
        SECOND_DNS_SERVER = "1.1.1.1"

        alpha = api.default_config_alpha_node()

        (connection_alpha, alpha_conn_tracker) = await exit_stack.enter_async_context(
            new_connection_with_conn_tracker(
                ConnectionTag.DOCKER_CONE_CLIENT_1,
                generate_connection_tracker_config(
                    ConnectionTag.DOCKER_CONE_CLIENT_1,
                ),
            )
        )

        process = await exit_stack.enter_async_context(
            connection_alpha.create_process(
                ["tcpdump", "-ni", "eth0", "udp", "and", "port", "53", "-l"]
            ).run()
        )

        client_alpha = await exit_stack.enter_async_context(
            telio.Client(connection_alpha, alpha,).run_meshnet(
                api.get_meshmap(alpha.id, derp_servers=[]),
            )
        )

        await client_alpha.enable_magic_dns([FIRST_DNS_SERVER, SECOND_DNS_SERVER])

        await testing.wait_normal(
            connection_alpha.create_process(
                ["nslookup", "google.com", DNS_SERVER_ADDRESS]
            ).execute(),
        )

        await asyncio.sleep(1)

        results = re.findall(
            r".* IP .* > (?P<dest_ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,5}): .* A\?.*",
            process.get_stdout(),
        )

        assert results
        assert [result for result in results if FIRST_DNS_SERVER in result]
        assert not ([result for result in results if SECOND_DNS_SERVER in result])
        assert alpha_conn_tracker.get_out_of_limits() is None


@pytest.mark.asyncio
async def test_dns_aaaa_records() -> None:
    async with AsyncExitStack() as exit_stack:
        api = API()
        (alpha, beta) = api.default_config_two_nodes()

        beta_ipv6 = "1234:5678:9abc:def0:1234:5678:9abc:def0"
        api.assign_ip(beta.id, beta_ipv6)

        connection_alpha = await exit_stack.enter_async_context(
            new_connection_by_tag(ConnectionTag.DOCKER_CONE_CLIENT_1)
        )

        client_alpha = await exit_stack.enter_async_context(
            telio.Client(connection_alpha, alpha).run_meshnet(
                api.get_meshmap(alpha.id),
            )
        )
        await client_alpha.enable_magic_dns(["1.1.1.1"])

        alpha_response = await testing.wait_long(
            connection_alpha.create_process(
                ["nslookup", "beta.nord", DNS_SERVER_ADDRESS]
            ).execute()
        )

        # 100.64.33.2
        assert beta.ip_addresses[0] in alpha_response.get_stdout()
        # 1234:5678:9abc:def0:1234:5678:9abc:def0
        assert beta.ip_addresses[1] in alpha_response.get_stdout()
