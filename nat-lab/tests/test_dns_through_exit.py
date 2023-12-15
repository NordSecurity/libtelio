import asyncio
import config
import pytest
import re
import telio
from contextlib import AsyncExitStack
from helpers import setup_mesh_nodes, SetupParameters
from typing import List, Tuple
from utils import testing
from utils.connection_tracker import ConnectionLimits
from utils.connection_util import generate_connection_tracker_config, ConnectionTag
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
            marks=[
                pytest.mark.ipv4v6,
                pytest.mark.xfail(reason="Test is flaky - LLT-4656"),
            ],
        ),
    ],
)
@pytest.mark.parametrize(
    "alpha_setup_params",
    [
        pytest.param(
            SetupParameters(
                connection_tag=ConnectionTag.DOCKER_CONE_CLIENT_1,
                adapter_type=telio.AdapterType.BoringTun,
                connection_tracker_config=generate_connection_tracker_config(
                    ConnectionTag.DOCKER_CONE_CLIENT_1,
                    derp_1_limits=ConnectionLimits(1, 1),
                ),
            ),
            marks=pytest.mark.xfail(reason="Test is flaky - LLT-4656"),
        ),
        pytest.param(
            SetupParameters(
                connection_tag=ConnectionTag.DOCKER_CONE_CLIENT_1,
                adapter_type=telio.AdapterType.LinuxNativeWg,
                connection_tracker_config=generate_connection_tracker_config(
                    ConnectionTag.DOCKER_CONE_CLIENT_1,
                    derp_1_limits=ConnectionLimits(1, 1),
                ),
            ),
            marks=pytest.mark.linux_native,
        ),
        # This test is failing, but currently is non critical
        # pytest.param(
        #     SetupParameters(
        #         connection_tag=ConnectionTag.MAC_VM,
        #         adapter_type=telio.AdapterType.BoringTun,
        #         connection_tracker_config=generate_connection_tracker_config(
        #             ConnectionTag.MAC_VM,
        #             derp_1_limits=ConnectionLimits(1, 1),
        #         ),
        #     ),
        #     marks=pytest.mark.mac,
        # ),
    ],
)
@pytest.mark.parametrize(
    "beta_setup_params",
    [
        pytest.param(
            SetupParameters(
                connection_tag=ConnectionTag.DOCKER_CONE_CLIENT_2,
                connection_tracker_config=generate_connection_tracker_config(
                    ConnectionTag.DOCKER_CONE_CLIENT_2,
                    derp_1_limits=ConnectionLimits(1, 1),
                ),
            )
        )
    ],
)
async def test_dns_through_exit(
    alpha_setup_params: SetupParameters,
    beta_setup_params: SetupParameters,
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

        env = await setup_mesh_nodes(
            exit_stack, [alpha_setup_params, beta_setup_params]
        )

        _, exit_node = env.nodes
        client_alpha, client_exit = env.clients
        connection_alpha, _ = [conn.connection for conn in env.connections]

        # entry connects to exit
        await testing.wait_long(client_exit.get_router().create_exit_node_route())

        await client_alpha.connect_to_exit_node(exit_node.public_key)

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
        await client_alpha.disconnect_from_exit_node(exit_node.public_key)

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
