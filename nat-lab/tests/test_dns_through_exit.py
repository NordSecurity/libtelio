from contextlib import AsyncExitStack
from mesh_api import API
from telio import AdapterType
from utils import ConnectionTag, new_connection_by_tag
import config
import pytest
import telio
import utils.testing as testing
import re


@pytest.mark.parametrize(
    "alpha_connection_tag,alpha_adapter_type",
    [
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
    alpha_connection_tag: ConnectionTag, alpha_adapter_type: AdapterType
) -> None:
    async with AsyncExitStack() as exit_stack:
        api = API()

        alpha = api.register(
            name="alpha",
            id="96ddb926-4b86-11ec-81d3-0242ac130003",
            private_key="mODRJKABR4wDCjXn899QO6wb83azXKZF7hcfX8dWuUA=",
            public_key="3XCOtCGl5tZJ8N5LksxkjfeqocW0BH2qmARD7qzHDkI=",
        )

        exit_node = api.register(
            name="exit-node",
            id="7b4548ca-fe5a-4597-8513-896f38c6d6ae",
            private_key="GN+D2Iy9p3UmyBZhgxU4AhbLT6sxY0SUhXu0a0TuiV4=",
            public_key="UnB+btGMEBXcR7EchMi28Hqk0Q142WokO6n313dt3mc=",
        )

        api.assign_ip(alpha.id, config.ALPHA_NODE_ADDRESS)
        api.assign_ip(exit_node.id, config.BETA_NODE_ADDRESS)

        exit_node.set_peer_firewall_settings(alpha.id, allow_incoming_connections=True)

        connection_alpha = await exit_stack.enter_async_context(
            new_connection_by_tag(alpha_connection_tag)
        )
        connection_exit = await exit_stack.enter_async_context(
            new_connection_by_tag(ConnectionTag.DOCKER_CONE_CLIENT_2)
        )

        client_alpha = await exit_stack.enter_async_context(
            telio.run_meshnet(
                connection_alpha,
                alpha,
                api.get_meshmap(alpha.id),
                alpha_adapter_type,
            )
        )

        client_exit = await exit_stack.enter_async_context(
            telio.run_meshnet(connection_exit, exit_node, api.get_meshmap(exit_node.id))
        )

        await testing.wait_long(client_alpha.handshake(exit_node.public_key))
        await testing.wait_long(client_exit.handshake(alpha.public_key))

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
