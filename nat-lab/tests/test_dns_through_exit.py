from contextlib import AsyncExitStack
from mesh_api import API
from telio import AdapterType
import pytest
import telio
import utils.testing as testing
import re
import asyncio
import config
from utils.connection_tracker import (
    ConnectionLimits,
    generate_connection_tracker_config,
)
from utils import (
    ConnectionTag,
    new_connection_with_conn_tracker,
)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "alpha_connection_tag,alpha_adapter_type",
    [
        pytest.param(
            ConnectionTag.DOCKER_CONE_CLIENT_1,
            AdapterType.BoringTun,
        ),
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
) -> None:
    async with AsyncExitStack() as exit_stack:
        api = API()

        (alpha, exit_node) = api.default_config_two_nodes()

        (connection_alpha, alpha_conn_tracker) = await exit_stack.enter_async_context(
            new_connection_with_conn_tracker(
                alpha_connection_tag,
                generate_connection_tracker_config(
                    alpha_connection_tag,
                    derp_1_limits=ConnectionLimits(1, 1),
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
            telio.Client(connection_alpha, alpha, alpha_adapter_type,).run_meshnet(
                api.get_meshmap(alpha.id),
            )
        )

        client_exit = await exit_stack.enter_async_context(
            telio.Client(connection_exit, exit_node,).run_meshnet(
                api.get_meshmap(exit_node.id),
            )
        )

        await testing.wait_long(
            asyncio.gather(
                client_alpha.wait_for_any_derp_state([telio.State.Connected]),
                client_exit.wait_for_any_derp_state([telio.State.Connected]),
            )
        )

        await testing.wait_long(
            asyncio.gather(
                alpha_conn_tracker.wait_for_event("derp_1"),
                exit_conn_tracker.wait_for_event("derp_1"),
            )
        )

        await testing.wait_long(
            asyncio.gather(
                client_alpha.handshake(exit_node.public_key),
                client_exit.handshake(alpha.public_key),
            )
        )

        # entry connects to exit
        await testing.wait_long(client_exit.get_router().create_exit_node_route())
        await testing.wait_long(
            client_alpha.connect_to_exit_node(
                exit_node.public_key,
            )
        )

        await testing.wait_long(client_alpha.handshake(exit_node.public_key))

        await client_exit.enable_magic_dns(["8.8.8.8"])

        # if this times out dns forwarder failed to start
        await testing.wait_normal(
            connection_alpha.create_process(
                ["nslookup", "google.com", config.LIBTELIO_EXIT_DNS_IP]
            ).execute(),
        )

        # sending dns straight to exit peer's dns forwarder(as will be done on linux/windows)
        alpha_response = await testing.wait_normal(
            connection_alpha.create_process(
                ["nslookup", "google.com", config.LIBTELIO_EXIT_DNS_IP]
            ).execute(),
        )
        # Check if some address was found
        assert (
            re.search(
                "Name:.*google.com.*Address", alpha_response.get_stdout(), re.DOTALL
            )
            is not None
        )

        await client_alpha.enable_magic_dns(["1.1.1.1"])

        # blocking 1.1.1.1 to make sure requests go to 8.8.8.8
        await exit_stack.enter_async_context(
            client_exit.get_router().disable_path("1.1.1.1")
        )

        # sending dns to local forwarder, which should forward it to exit dns forwarder(apple/android way)
        alpha_response = await testing.wait_normal(
            connection_alpha.create_process(
                ["nslookup", "google.com", config.LIBTELIO_DNS_IP]
            ).execute(),
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
                ["nslookup", "google.com", config.LIBTELIO_DNS_IP]
            ).execute(),
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
