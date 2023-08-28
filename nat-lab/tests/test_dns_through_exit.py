import asyncio
import config
import pytest
import re
import telio
from contextlib import AsyncExitStack
from mesh_api import API
from telio import AdapterType, State
from typing import List, Tuple
from utils import testing
from utils.connection_tracker import ConnectionLimits
from utils.connection_util import (
    generate_connection_tracker_config,
    ConnectionTag,
    new_connection_with_conn_tracker,
)
from utils.router import IPStack


# IPv6 tests are failing because we do not have IPV6 internet connection
@pytest.mark.asyncio
@pytest.mark.parametrize(
    "alpha_info",
    [
        pytest.param(
            (IPStack.IPv4, ["1.1.1.1"]),
            marks=pytest.mark.ipv4,
        ),
        # We're not tesing IPv6 here, cause we do not have IPv6 connectivity on exit-node
        # pytest.param(
        #     IPStack.IPv6,
        #     marks=pytest.mark.ipv6,
        # ),
        pytest.param(
            (IPStack.IPv4v6, ["1.1.1.1", "2606:4700:4700::1111"]),
            marks=pytest.mark.ipv4v6,
        ),
    ],
)
@pytest.mark.parametrize(
    "exit_info",
    [
        pytest.param(
            (IPStack.IPv4, ["8.8.8.8"]),
            marks=pytest.mark.ipv4,
        ),
        # We're not tesing IPv6 here, cause we do not have IPv6 connectivity on exit-node
        # pytest.param(
        #     IPStack.IPv6,
        #     marks=pytest.mark.ipv6,
        # ),
        pytest.param(
            (IPStack.IPv4v6, ["8.8.8.8", "2001:4860:4860::8888"]),
            marks=pytest.mark.ipv4v6,
        ),
    ],
)
@pytest.mark.parametrize(
    "alpha_connection_tag,alpha_adapter_type",
    [
        pytest.param(ConnectionTag.DOCKER_CONE_CLIENT_1, AdapterType.BoringTun),
        pytest.param(
            ConnectionTag.DOCKER_CONE_CLIENT_1,
            AdapterType.LinuxNativeWg,
            marks=pytest.mark.linux_native,
        ),
        # This test is failing, but currently is non critical
        # pytest.param(
        #     ConnectionTag.MAC_VM,
        #     AdapterType.BoringTun,
        #     marks=pytest.mark.mac,
        # ),
    ],
)
async def test_dns_through_exit(
    alpha_connection_tag: ConnectionTag,
    alpha_adapter_type: AdapterType,
    alpha_info: Tuple[IPStack, List[str]],
    exit_info: Tuple[IPStack, List[str]],
) -> None:
    async with AsyncExitStack() as exit_stack:
        if (alpha_info[0] == IPStack.IPv4 and exit_info[0] == IPStack.IPv6) or (
            alpha_info[0] == IPStack.IPv6 and exit_info[0] == IPStack.IPv4
        ):
            # Incompatible configurations
            pytest.skip()

        dns_server_address_exit = (
            config.LIBTELIO_DNS_IPV4
            if exit_info[0] in [IPStack.IPv4, IPStack.IPv4v6]
            else config.LIBTELIO_DNS_IPV6
        )
        dns_server_address_local = (
            config.LIBTELIO_DNS_IPV4
            if alpha_info[0] in [IPStack.IPv4, IPStack.IPv4v6]
            else config.LIBTELIO_DNS_IPV6
        )

        api = API()

        (alpha, exit_node) = api.default_config_two_nodes(
            alpha_ip_stack=alpha_info[0], beta_ip_stack=exit_info[0]
        )

        (connection_alpha, alpha_conn_tracker) = await exit_stack.enter_async_context(
            new_connection_with_conn_tracker(
                alpha_connection_tag,
                generate_connection_tracker_config(
                    alpha_connection_tag, derp_1_limits=ConnectionLimits(1, 1)
                ),
            )
        )
        (connection_exit, exit_conn_tracker) = await exit_stack.enter_async_context(
            new_connection_with_conn_tracker(
                ConnectionTag.DOCKER_CONE_CLIENT_2,
                generate_connection_tracker_config(
                    ConnectionTag.DOCKER_CONE_CLIENT_2,
                    derp_1_limits=ConnectionLimits(1, 1),
                ),
            )
        )

        client_alpha = await exit_stack.enter_async_context(
            telio.Client(connection_alpha, alpha, alpha_adapter_type).run(
                api.get_meshmap(alpha.id)
            )
        )

        client_exit = await exit_stack.enter_async_context(
            telio.Client(connection_exit, exit_node).run(api.get_meshmap(exit_node.id))
        )

        await testing.wait_lengthy(
            asyncio.gather(
                client_alpha.wait_for_state_on_any_derp([State.Connected]),
                client_exit.wait_for_state_on_any_derp([State.Connected]),
                alpha_conn_tracker.wait_for_event("derp_1"),
                exit_conn_tracker.wait_for_event("derp_1"),
            )
        )
        await testing.wait_lengthy(
            asyncio.gather(
                client_alpha.wait_for_state_peer(
                    exit_node.public_key, [State.Connected]
                ),
                client_exit.wait_for_state_peer(alpha.public_key, [State.Connected]),
            )
        )

        # entry connects to exit
        await testing.wait_long(client_exit.get_router().create_exit_node_route())
        await testing.wait_long(client_alpha.connect_to_exit_node(exit_node.public_key))

        await testing.wait_long(
            client_alpha.wait_for_event_peer(exit_node.public_key, [State.Connected])
        )

        await client_exit.enable_magic_dns(exit_info[1])

        # if this times out dns forwarder failed to start
        await testing.wait_normal(
            connection_alpha.create_process(
                ["nslookup", "google.com", dns_server_address_exit]
            ).execute()
        )

        # sending dns straight to exit peer's dns forwarder(as will be done on linux/windows)
        alpha_response = await testing.wait_normal(
            connection_alpha.create_process(
                ["nslookup", "google.com", dns_server_address_exit]
            ).execute()
        )
        # Check if some address was found
        assert (
            re.search(
                "Name:.*google.com.*Address", alpha_response.get_stdout(), re.DOTALL
            )
            is not None
        )

        await client_alpha.enable_magic_dns(alpha_info[1])

        async def disable_path(addr):
            await exit_stack.enter_async_context(
                client_exit.get_router().disable_path(addr)
            )

        # blocking 1.1.1.1 and its ipv6 counterpart] to make sure requests go to 8.8.8.8
        await testing.wait_lengthy(
            asyncio.gather(*[disable_path(addr) for addr in alpha_info[1]])
        )

        # sending dns to local forwarder, which should forward it to exit dns forwarder(apple/android way)
        alpha_response = await testing.wait_normal(
            connection_alpha.create_process(
                ["nslookup", "google.com", dns_server_address_local]
            ).execute()
        )
        # Check if some address was found
        assert (
            re.search(
                "Name:.*google.com.*Address", alpha_response.get_stdout(), re.DOTALL
            )
            is not None
        )
        await testing.wait_long(client_alpha.disconnect_from_exit_nodes())

        # local forwarder should resolve this, checking if forward ips are changed back correctly
        alpha_response = await testing.wait_normal(
            connection_alpha.create_process(
                ["nslookup", "google.com", dns_server_address_local]
            ).execute()
        )
        # Check if some address was found
        assert (
            re.search(
                "Name:.*google.com.*Address", alpha_response.get_stdout(), re.DOTALL
            )
            is not None
        )

        assert alpha_conn_tracker.get_out_of_limits() is None
        assert exit_conn_tracker.get_out_of_limits() is None
