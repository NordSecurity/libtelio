import asyncio
import pytest
from contextlib import AsyncExitStack
from tests import config
from tests.helpers import setup_api, setup_mesh_nodes, SetupParameters
from tests.utils.bindings import default_features, TelioAdapterType
from tests.utils.connection import ConnectionTag
from tests.utils.connection_util import generate_connection_tracker_config
from tests.utils.dns import query_dns
from tests.utils.router import IPStack
from tests.utils.testing import log_test_passed
from typing import List, Tuple


# IPv6 tests are failing because we do not have IPV6 internet connection
@pytest.mark.asyncio
@pytest.mark.parametrize(
    "alpha_info",
    [
        pytest.param(
            (IPStack.IPv4, ["10.0.80.82"]),
            marks=pytest.mark.ipv4,
            id="a_v4",
        ),
        # We're not tesing IPv6 here, cause we do not have IPv6 connectivity on exit-node
        # pytest.param(
        #     IPStack.IPv6,
        #     marks=pytest.mark.ipv6,
        # ),
        pytest.param(
            (IPStack.IPv4v6, ["10.0.80.82", "2001:db8:85a4::adda:edde:7"]),
            marks=pytest.mark.ipv4v6,
            id="a_v4v6",
        ),
    ],
)
@pytest.mark.parametrize(
    "exit_info",
    [
        pytest.param(
            (IPStack.IPv4, ["10.0.80.83"]),
            marks=pytest.mark.ipv4,
            id="e_v4",
        ),
        # We're not tesing IPv6 here, cause we do not have IPv6 connectivity on exit-node
        # pytest.param(
        #     IPStack.IPv6,
        #     marks=pytest.mark.ipv6,
        # ),
        pytest.param(
            (IPStack.IPv4v6, ["10.0.80.83", "2001:db8:85a4::adda:edde:8"]),
            marks=pytest.mark.ipv4v6,
            id="e_v4v6",
        ),
    ],
)
@pytest.mark.parametrize(
    "alpha_setup_params",
    [
        pytest.param(
            SetupParameters(
                connection_tag=ConnectionTag.DOCKER_CONE_CLIENT_1,
                adapter_type_override=TelioAdapterType.NEP_TUN,
                connection_tracker_config=generate_connection_tracker_config(
                    ConnectionTag.DOCKER_CONE_CLIENT_1,
                    derp_1_limits=(1, 1),
                ),
            ),
            id="a_neptun",
        ),
        pytest.param(
            SetupParameters(
                connection_tag=ConnectionTag.DOCKER_CONE_CLIENT_1,
                adapter_type_override=TelioAdapterType.LINUX_NATIVE_TUN,
                connection_tracker_config=generate_connection_tracker_config(
                    ConnectionTag.DOCKER_CONE_CLIENT_1,
                    derp_1_limits=(1, 1),
                ),
            ),
            marks=pytest.mark.linux_native,
            id="a_native",
        ),
        # This test is failing, but currently is non critical
        # pytest.param(
        #     SetupParameters(
        #         connection_tag=ConnectionTag.VM_MAC,
        #         adapter_type_override=TelioAdapterType.NEP_TUN,
        #         connection_tracker_config=generate_connection_tracker_config(
        #             ConnectionTag.VM_MAC,
        #             derp_1_limits=(1, 1),
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
                    derp_1_limits=(1, 1),
                ),
                features=default_features(enable_firewall_exclusion_range="10.0.0.0/8"),
            ),
            id="b",
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

        api, (alpha, beta) = setup_api(
            [(False, alpha_setup_params.ip_stack), (False, beta_setup_params.ip_stack)]
        )
        beta.set_peer_firewall_settings(
            alpha.id, allow_incoming_connections=True, allow_peer_traffic_routing=True
        )

        env = await setup_mesh_nodes(
            exit_stack,
            [alpha_setup_params, beta_setup_params],
            provided_api=api,
        )

        _, exit_node = env.nodes
        client_alpha, client_exit = env.clients
        connection_alpha, _ = [conn.connection for conn in env.connections]

        # entry connects to exit
        await client_exit.get_router().create_exit_node_route()

        await client_alpha.connect_to_exit_node(exit_node.public_key)

        await client_exit.enable_magic_dns(exit_info[1])

        # if this times out dns forwarder failed to start
        await query_dns(
            connection_alpha, "google.com", dns_server=dns_server_address_exit
        )

        # sending dns straight to exit peer's dns forwarder(as will be done on linux/windows)
        await query_dns(
            connection_alpha,
            "google.com",
            dns_server=dns_server_address_exit,
            expected_output=["Name:.*google.com.*Address"],
        )

        await client_alpha.enable_magic_dns(alpha_info[1])

        async def disable_path(addr):
            await exit_stack.enter_async_context(
                client_exit.get_router().disable_path(addr)
            )

        # blocking dns-server-1 and its ipv6 counterpart, to make sure requests go to dns-server-2
        await asyncio.gather(*[disable_path(addr) for addr in alpha_info[1]])

        # sending dns to local forwarder, which should forward it to exit dns forwarder(apple/android way)
        await query_dns(
            connection_alpha,
            "google.com",
            dns_server=dns_server_address_local,
            expected_output=["Name:.*google.com.*Address"],
            options=["-timeout=5"],
        )
        await client_alpha.disconnect_from_exit_node(exit_node.public_key)

        # local forwarder should resolve this, checking if forward ips are changed back correctly
        await query_dns(
            connection_alpha,
            "google.com",
            dns_server=dns_server_address_local,
            expected_output=["Name:.*google.com.*Address"],
        )

        # LLT-5532: To be cleaned up...
        client_alpha.allow_errors(
            ["telio_dns::nameserver.*Invalid protocol for DNS request"]
        )
        client_exit.allow_errors(
            ["telio_dns::nameserver.*Invalid protocol for DNS request"]
        )
        log_test_passed()
