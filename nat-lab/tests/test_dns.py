# pylint: disable=too-many-lines

import asyncio
import itertools
import pytest
from contextlib import AsyncExitStack
from tests import config, timeouts
from tests.config import LIBTELIO_DNS_IPV4, LIBTELIO_DNS_IPV6, LAN_ADDR_MAP
from tests.helpers import (
    SetupParameters,
    setup_api,
    setup_environment,
    setup_mesh_nodes,
    string_to_compressed_ipv6,
)
from tests.utils.bindings import default_features, FeatureDns, TelioAdapterType
from tests.utils.connection import ConnectionTag
from tests.utils.connection_tracker import (
    ConntrackerEvent,
    ConnTrackerViolation,
    ConnTrackerEventsValidator,
    FiveTuple,
    EventType as ConnTrackerEventType,
)
from tests.utils.connection_util import generate_connection_tracker_config
from tests.utils.dns import query_dns, query_dns_port
from tests.utils.process import ProcessExecError
from tests.utils.router import IPStack
from typing import List, Optional


def get_dns_server_address(ip_stack: IPStack) -> str:
    return (
        LIBTELIO_DNS_IPV4
        if ip_stack in [IPStack.IPv4, IPStack.IPv4v6]
        else LIBTELIO_DNS_IPV6
    )


# TODO: Linux native has to be removed
@pytest.mark.asyncio
@pytest.mark.parametrize(
    ["alpha_ip_stack", "alpha_setup_params"],
    [
        pytest.param(
            IPStack.IPv4,
            SetupParameters(
                connection_tag=ConnectionTag.DOCKER_CONE_CLIENT_1,
                adapter_type_override=TelioAdapterType.NEP_TUN,
                connection_tracker_config=generate_connection_tracker_config(
                    ConnectionTag.DOCKER_CONE_CLIENT_1,
                    derp_1_limits=(1, 1),
                ),
            ),
            marks=pytest.mark.ipv4,
        ),
        pytest.param(
            IPStack.IPv6,
            SetupParameters(
                connection_tag=ConnectionTag.DOCKER_CONE_CLIENT_1,
                adapter_type_override=TelioAdapterType.NEP_TUN,
                connection_tracker_config=generate_connection_tracker_config(
                    ConnectionTag.DOCKER_CONE_CLIENT_1,
                    derp_1_limits=(1, 1),
                ),
            ),
            marks=pytest.mark.ipv6,
        ),
        pytest.param(
            IPStack.IPv4v6,
            SetupParameters(
                connection_tag=ConnectionTag.DOCKER_CONE_CLIENT_1,
                adapter_type_override=TelioAdapterType.NEP_TUN,
                connection_tracker_config=generate_connection_tracker_config(
                    ConnectionTag.DOCKER_CONE_CLIENT_1,
                    derp_1_limits=(1, 1),
                ),
            ),
            marks=pytest.mark.ipv4v6,
        ),
    ],
)
@pytest.mark.parametrize(
    "beta_ip_stack",
    [
        pytest.param(
            IPStack.IPv4,
            marks=pytest.mark.ipv4,
        ),
        pytest.param(
            IPStack.IPv6,
            marks=pytest.mark.ipv6,
        ),
        pytest.param(
            IPStack.IPv4v6,
            marks=pytest.mark.ipv4v6,
        ),
    ],
)
async def test_dns(
    alpha_ip_stack: IPStack,
    alpha_setup_params: SetupParameters,
    beta_ip_stack: IPStack,
) -> None:
    async with AsyncExitStack() as exit_stack:
        dns_server_address_alpha = get_dns_server_address(alpha_ip_stack)
        dns_server_address_beta = (
            LIBTELIO_DNS_IPV4 if beta_ip_stack == IPStack.IPv4 else LIBTELIO_DNS_IPV6
        )
        env = await setup_mesh_nodes(
            exit_stack,
            [
                alpha_setup_params,
                SetupParameters(
                    connection_tag=ConnectionTag.DOCKER_CONE_CLIENT_2,
                    connection_tracker_config=generate_connection_tracker_config(
                        ConnectionTag.DOCKER_CONE_CLIENT_2,
                        derp_1_limits=(1, 1),
                    ),
                ),
            ],
        )
        alpha, beta = env.nodes
        client_alpha, client_beta = env.clients
        connection_alpha, connection_beta = [
            conn.connection for conn in env.connections
        ]

        # These calls should timeout without returning anything, but cache the peer addresses
        with pytest.raises(ProcessExecError):
            await query_dns(
                connection_alpha, "google.com", dns_server=dns_server_address_alpha
            )

        with pytest.raises(ProcessExecError):
            await query_dns(
                connection_beta, "google.com", dns_server=dns_server_address_beta
            )

        await client_alpha.enable_magic_dns(["10.0.80.82"])
        await client_beta.enable_magic_dns(["10.0.80.82"])

        # If everything went correctly, these calls should not timeout
        await query_dns(
            connection_alpha, "google.com", dns_server=dns_server_address_alpha
        )
        await query_dns(
            connection_beta, "google.com", dns_server=dns_server_address_beta
        )

        # If the previous calls didn't fail, we can assume that the resolver is running so no need to wait for the timeout and test the validity of the response
        await query_dns(
            connection_alpha,
            "beta.nord",
            string_to_compressed_ipv6(beta.ip_addresses),
            dns_server_address_alpha,
        )
        await query_dns(
            connection_beta,
            "alpha.nord",
            string_to_compressed_ipv6(alpha.ip_addresses),
            dns_server_address_beta,
        )

        # Testing if instance can get the IP of self from DNS. See LLT-4246 for more details.
        await query_dns(
            connection_alpha,
            "alpha.nord",
            string_to_compressed_ipv6(alpha.ip_addresses),
            dns_server_address_alpha,
        )

        # Now we disable magic dns
        await client_alpha.disable_magic_dns()
        await client_beta.disable_magic_dns()

        # And as a result these calls should timeout again
        with pytest.raises(ProcessExecError):
            await query_dns(
                connection_alpha, "google.com", dns_server=dns_server_address_alpha
            )
        with pytest.raises(ProcessExecError):
            await query_dns(
                connection_beta, "google.com", dns_server=dns_server_address_beta
            )


# TODO: Linux native has to be removed
@pytest.mark.asyncio
@pytest.mark.parametrize(
    ["alpha_ip_stack", "alpha_setup_params"],
    [
        pytest.param(
            IPStack.IPv4,
            SetupParameters(
                connection_tag=ConnectionTag.DOCKER_CONE_CLIENT_1,
                adapter_type_override=TelioAdapterType.NEP_TUN,
                connection_tracker_config=generate_connection_tracker_config(
                    ConnectionTag.DOCKER_CONE_CLIENT_1,
                    derp_1_limits=(1, 1),
                ),
            ),
            marks=pytest.mark.ipv4,
        ),
        pytest.param(
            IPStack.IPv6,
            SetupParameters(
                connection_tag=ConnectionTag.DOCKER_CONE_CLIENT_1,
                adapter_type_override=TelioAdapterType.NEP_TUN,
                connection_tracker_config=generate_connection_tracker_config(
                    ConnectionTag.DOCKER_CONE_CLIENT_1,
                    derp_1_limits=(1, 1),
                ),
            ),
            marks=pytest.mark.ipv6,
        ),
        pytest.param(
            IPStack.IPv4v6,
            SetupParameters(
                connection_tag=ConnectionTag.DOCKER_CONE_CLIENT_1,
                adapter_type_override=TelioAdapterType.NEP_TUN,
                connection_tracker_config=generate_connection_tracker_config(
                    ConnectionTag.DOCKER_CONE_CLIENT_1,
                    derp_1_limits=(1, 1),
                ),
            ),
            marks=pytest.mark.ipv4v6,
        ),
    ],
)
async def test_dns_port(
    alpha_ip_stack: IPStack,
    alpha_setup_params: SetupParameters,
) -> None:
    async with AsyncExitStack() as exit_stack:
        dns_server_address_alpha = get_dns_server_address(alpha_ip_stack)
        env = await setup_mesh_nodes(
            exit_stack,
            [
                alpha_setup_params,
                SetupParameters(
                    connection_tag=ConnectionTag.DOCKER_CONE_CLIENT_2,
                    ip_stack=IPStack.IPv4v6,
                    connection_tracker_config=generate_connection_tracker_config(
                        ConnectionTag.DOCKER_CONE_CLIENT_2,
                        derp_1_limits=(1, 1),
                    ),
                ),
            ],
        )
        _, beta = env.nodes
        client_alpha, client_beta = env.clients
        connection_alpha, _ = [conn.connection for conn in env.connections]

        # These call should timeout without returning anything
        with pytest.raises(ProcessExecError):
            await query_dns_port(
                connection_alpha,
                "53",
                "www.google.com",
                dns_server_address_alpha,
            )

        await client_alpha.enable_magic_dns(["10.0.80.82"])
        await client_beta.enable_magic_dns(["10.0.80.82"])

        # A DNS request on port 53 should work
        await query_dns_port(
            connection_alpha,
            "53",
            "www.google.com",
            dns_server_address_alpha,
        )

        # A DNS request on a different port should timeout
        with pytest.raises(ProcessExecError):
            await query_dns_port(
                connection_alpha,
                "54",
                "www.google.com",
                dns_server_address_alpha,
            )

        # Look for beta on 53 port should work
        await query_dns_port(
            connection_alpha,
            "53",
            "beta.nord",
            dns_server_address_alpha,
            string_to_compressed_ipv6(beta.ip_addresses),
            extra_host_options=["A", "beta.nord", "AAAA"],
        )

        # Look for beta on a different port should timeout
        with pytest.raises(ProcessExecError):
            await query_dns_port(
                connection_alpha,
                "54",
                "beta.nord",
                dns_server_address_alpha,
            )

        # Disable magic dns
        await client_alpha.disable_magic_dns()
        await client_beta.disable_magic_dns()

        # And as a result these calls should timeout again
        with pytest.raises(ProcessExecError):
            await query_dns_port(
                connection_alpha,
                "53",
                "google.com",
                dns_server_address_alpha,
            )

        with pytest.raises(ProcessExecError):
            await query_dns_port(
                connection_alpha,
                "53",
                "beta.nord",
                dns_server_address_alpha,
            )

        # LLT-5532: To be cleaned up...
        client_alpha.allow_errors(["telio_dns::nameserver.*Invalid DNS port"])


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "alpha_ip_stack",
    [
        pytest.param(
            IPStack.IPv4,
            marks=pytest.mark.ipv4,
        ),
        pytest.param(
            IPStack.IPv6,
            marks=pytest.mark.ipv6,
        ),
        pytest.param(
            IPStack.IPv4v6,
            marks=pytest.mark.ipv4v6,
        ),
    ],
)
async def test_vpn_dns(alpha_ip_stack: IPStack) -> None:
    async with AsyncExitStack() as exit_stack:
        dns_server_address = get_dns_server_address(alpha_ip_stack)
        env = await exit_stack.enter_async_context(
            setup_environment(
                exit_stack,
                [
                    SetupParameters(
                        connection_tag=ConnectionTag.DOCKER_CONE_CLIENT_1,
                        ip_stack=alpha_ip_stack,
                        connection_tracker_config=generate_connection_tracker_config(
                            ConnectionTag.DOCKER_CONE_CLIENT_1,
                            vpn_1_limits=(1, 1),
                        ),
                        is_meshnet=False,
                    )
                ],
                prepare_vpn=True,
            )
        )
        api = env.api
        alpha, *_ = env.nodes
        client_alpha, *_ = env.clients
        connection, *_ = [conn.connection for conn in env.connections]

        wg_server = config.WG_SERVER

        await client_alpha.connect_to_vpn(
            str(wg_server["ipv4"]), int(wg_server["port"]), str(wg_server["public_key"])
        )

        # After we connect to the VPN, enable magic DNS
        await client_alpha.enable_magic_dns(["10.0.80.82"])

        # Test to see if the module is working correctly
        await query_dns(connection, "google.com", dns_server=dns_server_address)

        # Test if the DNS module preserves CNAME records
        await query_dns(
            connection,
            "www.microsoft.com",
            ["canonical name"],
            dns_server_address,
            ["-q=CNAME"],
        )

        # Turn off the module and see if it worked
        await client_alpha.disable_magic_dns()

        with pytest.raises(ProcessExecError):
            await query_dns(connection, "google.com", dns_server=dns_server_address)

        # Test interop with meshnet
        await client_alpha.enable_magic_dns(["10.0.80.82"])
        await client_alpha.set_meshnet_config(
            api.get_meshnet_config(alpha.id, derp_servers=[])
        )

        await query_dns(connection, "google.com", dns_server=dns_server_address)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "alpha_ip_stack",
    [
        pytest.param(
            IPStack.IPv4,
            marks=pytest.mark.ipv4,
        ),
        pytest.param(
            IPStack.IPv6,
            marks=pytest.mark.ipv6,
        ),
        pytest.param(
            IPStack.IPv4v6,
            marks=pytest.mark.ipv4v6,
        ),
    ],
)
async def test_dns_after_mesh_off(alpha_ip_stack: IPStack) -> None:
    async with AsyncExitStack() as exit_stack:
        dns_server_address = get_dns_server_address(alpha_ip_stack)
        api, (_, beta) = setup_api([(False, alpha_ip_stack), (False, IPStack.IPv4v6)])
        env = await exit_stack.enter_async_context(
            setup_environment(
                exit_stack,
                [
                    SetupParameters(
                        connection_tag=ConnectionTag.DOCKER_CONE_CLIENT_1,
                        connection_tracker_config=generate_connection_tracker_config(
                            ConnectionTag.DOCKER_CONE_CLIENT_1
                        ),
                        derp_servers=[],
                        features=default_features(enable_ipv6=True),
                    )
                ],
                provided_api=api,
            )
        )
        connection_alpha, *_ = [conn.connection for conn in env.connections]
        client_alpha, *_ = env.clients

        # These calls should timeout without returning anything, but cache the peer addresses
        with pytest.raises(ProcessExecError):
            await query_dns(
                connection_alpha, "google.com", dns_server=dns_server_address
            )

        await client_alpha.enable_magic_dns(["10.0.80.82"])

        # If everything went correctly, these calls should not timeout
        await query_dns(connection_alpha, "google.com", dns_server=dns_server_address)

        # If the previous calls didn't fail, we can assume that the resolver is running so no need to wait for the timeout and test the validity of the response
        await query_dns(
            connection_alpha,
            "beta.nord",
            string_to_compressed_ipv6(beta.ip_addresses),
            dns_server_address,
        )

        # Now we disable magic dns
        await client_alpha.set_mesh_off()

        # If everything went correctly, these calls should not timeout
        await query_dns(connection_alpha, "google.com", dns_server=dns_server_address)

        # After mesh off, .nord names should not be resolved anymore, therefore nslookup should fail
        try:
            await query_dns(
                connection_alpha, "beta.nord", dns_server=dns_server_address
            )
        except ProcessExecError as e:
            assert "server can't find beta.nord" in e.stdout


@pytest.mark.asyncio
@pytest.mark.long
@pytest.mark.timeout(timeouts.TEST_DNS_STABILITY_TIMEOUT)
@pytest.mark.parametrize(
    "alpha_ip_stack",
    [
        pytest.param(
            IPStack.IPv4,
            marks=pytest.mark.ipv4,
        ),
        pytest.param(
            IPStack.IPv6,
            marks=pytest.mark.ipv6,
        ),
        pytest.param(
            IPStack.IPv4v6,
            marks=pytest.mark.ipv4v6,
        ),
    ],
)
async def test_dns_stability(alpha_ip_stack: IPStack) -> None:
    async with AsyncExitStack() as exit_stack:
        dns_server_address = get_dns_server_address(alpha_ip_stack)
        env = await setup_mesh_nodes(
            exit_stack,
            [
                SetupParameters(
                    connection_tag=ConnectionTag.DOCKER_CONE_CLIENT_1,
                    ip_stack=alpha_ip_stack,
                    adapter_type_override=TelioAdapterType.NEP_TUN,
                    connection_tracker_config=generate_connection_tracker_config(
                        ConnectionTag.DOCKER_CONE_CLIENT_1,
                        derp_1_limits=(1, 1),
                    ),
                ),
                SetupParameters(
                    connection_tag=ConnectionTag.DOCKER_CONE_CLIENT_2,
                    ip_stack=IPStack.IPv4v6,
                    connection_tracker_config=generate_connection_tracker_config(
                        ConnectionTag.DOCKER_CONE_CLIENT_2,
                        derp_1_limits=(1, 1),
                    ),
                ),
            ],
        )
        alpha, beta = env.nodes
        client_alpha, client_beta = env.clients
        connection_alpha, connection_beta = [
            conn.connection for conn in env.connections
        ]

        await client_alpha.enable_magic_dns(["10.0.80.82"])
        await client_beta.enable_magic_dns(["10.0.80.82"])

        await query_dns(connection_alpha, "google.com", dns_server=dns_server_address)
        await query_dns(connection_beta, "google.com", dns_server=dns_server_address)

        await query_dns(
            connection_alpha,
            "beta.nord",
            string_to_compressed_ipv6(beta.ip_addresses),
            dns_server_address,
        )
        await query_dns(
            connection_beta,
            "alpha.nord",
            string_to_compressed_ipv6(alpha.ip_addresses),
            dns_server_address,
        )

        await asyncio.sleep(60 * 5)

        await query_dns(connection_alpha, "google.com", dns_server=dns_server_address)
        await query_dns(connection_beta, "google.com", dns_server=dns_server_address)

        await query_dns(
            connection_alpha,
            "beta.nord",
            string_to_compressed_ipv6(beta.ip_addresses),
            dns_server_address,
        )
        await query_dns(
            connection_beta,
            "alpha.nord",
            string_to_compressed_ipv6(alpha.ip_addresses),
            dns_server_address,
        )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "alpha_ip_stack",
    [
        pytest.param(
            IPStack.IPv4,
            marks=pytest.mark.ipv4,
        ),
        pytest.param(
            IPStack.IPv6,
            marks=pytest.mark.ipv6,
        ),
        pytest.param(
            IPStack.IPv4v6,
            marks=pytest.mark.ipv4v6,
        ),
    ],
)
async def test_set_meshnet_config_dns_update(
    alpha_ip_stack: IPStack,
) -> None:
    async with AsyncExitStack() as exit_stack:
        dns_server_address = get_dns_server_address(alpha_ip_stack)
        env = await exit_stack.enter_async_context(
            setup_environment(
                exit_stack,
                [
                    SetupParameters(
                        connection_tag=ConnectionTag.DOCKER_CONE_CLIENT_1,
                        ip_stack=alpha_ip_stack,
                        connection_tracker_config=generate_connection_tracker_config(
                            ConnectionTag.DOCKER_CONE_CLIENT_1
                        ),
                        derp_servers=[],
                    )
                ],
            )
        )
        api = env.api
        alpha, *_ = env.nodes
        connection_alpha, *_ = [conn.connection for conn in env.connections]
        client_alpha, *_ = env.clients

        await client_alpha.enable_magic_dns([])

        # We should not be able to resolve beta yet, since it's not registered
        try:
            await query_dns(
                connection_alpha, "beta.nord", dns_server=dns_server_address
            )
        except ProcessExecError as e:
            assert "server can't find beta.nord" in e.stdout

        beta = api.default_config_one_node(ip_stack=IPStack.IPv4v6)

        # Check if setting meshnet updates nord names for dns resolver
        await client_alpha.set_meshnet_config(
            api.get_meshnet_config(alpha.id, derp_servers=[])
        )

        await query_dns(
            connection_alpha,
            "beta.nord",
            string_to_compressed_ipv6([beta.ip_addresses[0]]),
            dns_server_address,
        )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "alpha_ip_stack",
    [
        pytest.param(
            IPStack.IPv4,
            marks=pytest.mark.ipv4,
        ),
        pytest.param(
            IPStack.IPv6,
            marks=pytest.mark.ipv6,
        ),
        pytest.param(
            IPStack.IPv4v6,
            marks=pytest.mark.ipv4v6,
        ),
    ],
)
async def test_dns_update(alpha_ip_stack: IPStack) -> None:
    async with AsyncExitStack() as exit_stack:
        dns_server_address = get_dns_server_address(alpha_ip_stack)
        env = await exit_stack.enter_async_context(
            setup_environment(
                exit_stack,
                [
                    SetupParameters(
                        connection_tag=ConnectionTag.DOCKER_CONE_CLIENT_1,
                        ip_stack=alpha_ip_stack,
                        connection_tracker_config=generate_connection_tracker_config(
                            ConnectionTag.DOCKER_CONE_CLIENT_1,
                            vpn_1_limits=(1, 1),
                        ),
                        is_meshnet=False,
                    )
                ],
                prepare_vpn=True,
            )
        )
        connection, *_ = [conn.connection for conn in env.connections]
        client_alpha, *_ = env.clients

        wg_server = config.WG_SERVER

        await client_alpha.connect_to_vpn(
            str(wg_server["ipv4"]), int(wg_server["port"]), str(wg_server["public_key"])
        )

        # Don't forward anything yet
        await client_alpha.enable_magic_dns([])

        with pytest.raises(ProcessExecError):
            await query_dns(connection, "google.com", dns_server=dns_server_address)

        # Update forward dns and check if it works now
        await client_alpha.enable_magic_dns(["10.0.80.82"])

        await query_dns(
            connection, "google.com", ["Name:	google.com\nAddress:"], dns_server_address
        )

        # LLT-5532: To be cleaned up...
        client_alpha.allow_errors([
            "telio_dns::nameserver.*Lookup failed Error performing lookup: Unknown response code"
        ])


@pytest.mark.asyncio
async def test_dns_duplicate_requests_on_multiple_forward_servers() -> None:
    async with AsyncExitStack() as exit_stack:
        FIRST_DNS_SERVER = "10.0.80.83"
        SECOND_DNS_SERVER = "10.0.80.82"

        # Define conntracker validator which allows exactly one connection to either
        # FIRST or SECOND dns servers.
        class SingleConnectionToAnyNatlabDNS(ConnTrackerEventsValidator):
            def __init__(self):
                pass

            def find_conntracker_violations(
                self, events: List[ConntrackerEvent]
            ) -> Optional[ConnTrackerViolation]:
                new_connection_events = list(
                    filter(lambda e: e.event_type == ConnTrackerEventType.NEW, events)
                )
                if len(new_connection_events) != 1:
                    return ConnTrackerViolation(
                        recoverable=True,
                        reason=f"Only single connection to DNS server expected. Got {events}",
                    )
                allowed_five_tuples = [
                    FiveTuple(
                        protocol="udp",
                        src_ip=LAN_ADDR_MAP[ConnectionTag.DOCKER_CONE_CLIENT_1][
                            "primary"
                        ],
                        dst_ip=FIRST_DNS_SERVER,
                        dst_port=53,
                    ),
                    FiveTuple(
                        protocol="udp",
                        src_ip=LAN_ADDR_MAP[ConnectionTag.DOCKER_CONE_CLIENT_1][
                            "primary"
                        ],
                        dst_ip=SECOND_DNS_SERVER,
                        dst_port=53,
                    ),
                ]

                if not any(
                    map(
                        lambda ft: ft.partial_eq(new_connection_events[0].five_tuple),
                        allowed_five_tuples,
                    )
                ):
                    return ConnTrackerViolation(
                        recoverable=False,
                        reason=f"Only DNS connection was expected, got: {events}",
                    )

                return None

        env = await setup_mesh_nodes(
            exit_stack,
            [
                SetupParameters(
                    connection_tag=ConnectionTag.DOCKER_CONE_CLIENT_1,
                    ip_stack=IPStack.IPv4v6,
                    connection_tracker_config=[SingleConnectionToAnyNatlabDNS()],
                    derp_servers=[],
                )
            ],
        )
        connection_alpha, *_ = [conn.connection for conn in env.connections]
        client_alpha, *_ = env.clients

        await client_alpha.enable_magic_dns([FIRST_DNS_SERVER, SECOND_DNS_SERVER])
        await query_dns(
            connection_alpha, "google.com", options=["-timeout=1", "-type=a"]
        )


@pytest.mark.asyncio
async def test_dns_aaaa_records() -> None:
    async with AsyncExitStack() as exit_stack:
        api, (_, beta) = setup_api([(False, IPStack.IPv4v6), (False, IPStack.IPv4v6)])
        env = await exit_stack.enter_async_context(
            setup_environment(exit_stack, [SetupParameters()], provided_api=api)
        )
        connection_alpha, *_ = [conn.connection for conn in env.connections]
        client_alpha, *_ = env.clients

        await client_alpha.enable_magic_dns(["10.0.80.82"])

        await query_dns(
            connection_alpha, "beta.nord", string_to_compressed_ipv6(beta.ip_addresses)
        )


@pytest.mark.asyncio
async def test_dns_nickname() -> None:
    async with AsyncExitStack() as exit_stack:
        api, (alpha, beta) = setup_api(
            [(False, IPStack.IPv4v6), (False, IPStack.IPv4v6)]
        )
        api.assign_nickname(alpha.id, "johnny")
        api.assign_nickname(beta.id, "yOKo")

        env = await setup_mesh_nodes(
            exit_stack,
            [
                SetupParameters(
                    connection_tag=ConnectionTag.DOCKER_CONE_CLIENT_1,
                    connection_tracker_config=generate_connection_tracker_config(
                        ConnectionTag.DOCKER_CONE_CLIENT_1,
                        derp_1_limits=(1, 1),
                    ),
                    features=default_features(enable_nicknames=True),
                ),
                SetupParameters(
                    connection_tag=ConnectionTag.DOCKER_CONE_CLIENT_2,
                    connection_tracker_config=generate_connection_tracker_config(
                        ConnectionTag.DOCKER_CONE_CLIENT_2,
                        derp_1_limits=(1, 1),
                    ),
                    features=default_features(enable_nicknames=True),
                ),
            ],
            provided_api=api,
        )
        client_alpha, client_beta = env.clients
        connection_alpha, connection_beta = [
            conn.connection for conn in env.connections
        ]

        await client_alpha.enable_magic_dns([])
        await client_beta.enable_magic_dns([])

        await query_dns(
            connection_alpha, "yoko.nord", string_to_compressed_ipv6(beta.ip_addresses)
        )
        await query_dns(
            connection_alpha,
            "johnny.nord",
            string_to_compressed_ipv6(alpha.ip_addresses),
        )

        await query_dns(
            connection_beta,
            "johnny.nord",
            string_to_compressed_ipv6(alpha.ip_addresses),
        )
        await query_dns(
            connection_beta, "yOKo.nord", string_to_compressed_ipv6(beta.ip_addresses)
        )


@pytest.mark.asyncio
async def test_dns_change_nickname() -> None:
    async with AsyncExitStack() as exit_stack:
        api, (alpha, beta) = setup_api(
            [(False, IPStack.IPv4v6), (False, IPStack.IPv4v6)]
        )
        api.assign_nickname(alpha.id, "johnny")
        api.assign_nickname(beta.id, "yoko")
        env = await setup_mesh_nodes(
            exit_stack,
            [
                SetupParameters(
                    connection_tag=ConnectionTag.DOCKER_CONE_CLIENT_1,
                    connection_tracker_config=generate_connection_tracker_config(
                        ConnectionTag.DOCKER_CONE_CLIENT_1,
                        derp_1_limits=(1, 1),
                    ),
                    features=default_features(enable_nicknames=True),
                ),
                SetupParameters(
                    connection_tag=ConnectionTag.DOCKER_CONE_CLIENT_2,
                    connection_tracker_config=generate_connection_tracker_config(
                        ConnectionTag.DOCKER_CONE_CLIENT_2,
                        derp_1_limits=(1, 1),
                    ),
                    features=default_features(enable_nicknames=True),
                ),
            ],
            provided_api=api,
        )
        client_alpha, client_beta = env.clients
        connection_alpha, connection_beta = [
            conn.connection for conn in env.connections
        ]

        await client_alpha.enable_magic_dns([])
        await client_beta.enable_magic_dns([])

        # Set new meshnet config with different nicknames
        api.assign_nickname(alpha.id, "rotten")
        api.assign_nickname(beta.id, "ono")
        await client_alpha.set_meshnet_config(
            api.get_meshnet_config(alpha.id, derp_servers=[])
        )
        await client_beta.set_meshnet_config(
            api.get_meshnet_config(beta.id, derp_servers=[])
        )

        with pytest.raises(ProcessExecError):
            await query_dns(connection_alpha, "yoko.nord")
        with pytest.raises(ProcessExecError):
            await query_dns(connection_alpha, "johnny.nord")
        with pytest.raises(ProcessExecError):
            await query_dns(connection_beta, "yoko.nord")
        with pytest.raises(ProcessExecError):
            await query_dns(connection_beta, "johnny.nord")

        await query_dns(
            connection_alpha, "ono.nord", string_to_compressed_ipv6(beta.ip_addresses)
        )
        await query_dns(
            connection_alpha,
            "rotten.nord",
            string_to_compressed_ipv6(alpha.ip_addresses),
        )

        await query_dns(
            connection_beta,
            "rotten.nord",
            string_to_compressed_ipv6(alpha.ip_addresses),
        )
        await query_dns(
            connection_beta, "ono.nord", string_to_compressed_ipv6(beta.ip_addresses)
        )

        # Set new meshnet config removing nicknames
        api.reset_nickname(alpha.id)
        api.reset_nickname(beta.id)
        await client_alpha.set_meshnet_config(
            api.get_meshnet_config(alpha.id, derp_servers=[])
        )
        await client_beta.set_meshnet_config(
            api.get_meshnet_config(beta.id, derp_servers=[])
        )

        with pytest.raises(ProcessExecError):
            await query_dns(connection_alpha, "ono.nord")

        with pytest.raises(ProcessExecError):
            await query_dns(connection_alpha, "rotten.nord")

        with pytest.raises(ProcessExecError):
            await query_dns(connection_beta, "rotten.nord")

        with pytest.raises(ProcessExecError):
            await query_dns(connection_beta, "ono.nord")


@pytest.mark.asyncio
async def test_dns_wildcarded_records() -> None:
    async with AsyncExitStack() as exit_stack:
        api, (alpha, beta) = setup_api(
            [(False, IPStack.IPv4v6), (False, IPStack.IPv4v6)]
        )
        api.assign_nickname(alpha.id, "johnny")
        api.assign_nickname(beta.id, "yoko")
        env = await setup_mesh_nodes(
            exit_stack,
            [
                SetupParameters(
                    connection_tag=ConnectionTag.DOCKER_CONE_CLIENT_1,
                    connection_tracker_config=generate_connection_tracker_config(
                        ConnectionTag.DOCKER_CONE_CLIENT_1,
                        derp_1_limits=(1, 1),
                    ),
                    features=default_features(enable_nicknames=True),
                ),
                SetupParameters(
                    connection_tag=ConnectionTag.DOCKER_CONE_CLIENT_2,
                    connection_tracker_config=generate_connection_tracker_config(
                        ConnectionTag.DOCKER_CONE_CLIENT_2,
                        derp_1_limits=(1, 1),
                    ),
                    features=default_features(enable_nicknames=True),
                ),
            ],
            provided_api=api,
        )
        client_alpha, client_beta = env.clients
        connection_alpha, connection_beta = [
            conn.connection for conn in env.connections
        ]

        await client_alpha.enable_magic_dns([])
        await client_beta.enable_magic_dns([])

        await query_dns(
            connection_alpha,
            "myserviceA.alpha.nord",
            string_to_compressed_ipv6(alpha.ip_addresses),
        )
        await query_dns(
            connection_alpha,
            "myserviceB.johnny.nord",
            string_to_compressed_ipv6(alpha.ip_addresses),
        )
        await query_dns(
            connection_alpha,
            "herservice.yoko.nord",
            string_to_compressed_ipv6(beta.ip_addresses),
        )

        await query_dns(
            connection_beta,
            "myserviceC.beta.nord",
            string_to_compressed_ipv6(beta.ip_addresses),
        )
        await query_dns(
            connection_beta,
            "myserviceD.yoko.nord",
            string_to_compressed_ipv6(beta.ip_addresses),
        )
        await query_dns(
            connection_beta,
            "hisservice.johnny.nord",
            string_to_compressed_ipv6(alpha.ip_addresses),
        )


@pytest.mark.asyncio
async def test_dns_ttl_value() -> None:
    async with AsyncExitStack() as exit_stack:
        FIRST_DNS_SERVER = "10.0.80.83"
        SECOND_DNS_SERVER = "10.0.80.82"

        EXPECTED_TTL_VALUE = 1234

        features_without_exit_dns = default_features()
        features_without_exit_dns.dns = FeatureDns(
            exit_dns=None, ttl_value=EXPECTED_TTL_VALUE
        )

        api, (_, _) = setup_api([(False, IPStack.IPv4v6), (False, IPStack.IPv4v6)])
        env = await setup_mesh_nodes(
            exit_stack,
            [
                SetupParameters(
                    connection_tag=ConnectionTag.DOCKER_CONE_CLIENT_1,
                    connection_tracker_config=generate_connection_tracker_config(
                        ConnectionTag.DOCKER_CONE_CLIENT_1,
                        derp_1_limits=(1, 1),
                    ),
                    features=features_without_exit_dns,
                ),
                SetupParameters(
                    connection_tag=ConnectionTag.DOCKER_CONE_CLIENT_2,
                    connection_tracker_config=generate_connection_tracker_config(
                        ConnectionTag.DOCKER_CONE_CLIENT_2,
                        derp_1_limits=(1, 1),
                    ),
                ),
            ],
            provided_api=api,
        )
        client_alpha, *_ = env.clients
        connection_alpha, *_ = [conn.connection for conn in env.connections]

        await client_alpha.enable_magic_dns([FIRST_DNS_SERVER, SECOND_DNS_SERVER])
        await asyncio.sleep(1)

        process = await connection_alpha.create_process([
            "dig",
            "+noall",
            "+nocmd",
            "+answer",
            "alpha.nord",
            "@100.64.0.2",
        ]).execute()

        dig_stdout = process.get_stdout()
        dig_stderr = process.get_stderr()

        actual_ttl_value = int(dig_stdout.strip().split()[1])

        assert (
            actual_ttl_value == EXPECTED_TTL_VALUE
        ), f"dig stdout:\n{dig_stdout}\ndig stderr:\n{dig_stderr}"


@pytest.mark.asyncio
async def test_dns_nickname_in_any_case() -> None:
    async with AsyncExitStack() as exit_stack:
        api, (_, beta) = setup_api([(False, IPStack.IPv4v6), (False, IPStack.IPv4v6)])

        api.assign_nickname(beta.id, "yoko")

        env = await exit_stack.enter_async_context(
            setup_environment(
                exit_stack,
                [SetupParameters(features=default_features(enable_nicknames=True))],
                provided_api=api,
            )
        )
        connection_alpha, *_ = [conn.connection for conn in env.connections]
        client_alpha, *_ = env.clients

        await client_alpha.enable_magic_dns([])

        queries = [
            query_dns(
                connection_alpha,
                f"{name}.nord",
                string_to_compressed_ipv6(beta.ip_addresses),
            )
            for name in all_cases("yoko")
        ]

        await asyncio.gather(*queries)


def all_cases(name: str) -> List[str]:
    return [
        "".join(i) for i in itertools.product(*([c.lower(), c.upper()] for c in name))
    ]


@pytest.mark.asyncio
async def test_dns_no_error_return_code() -> None:
    async with AsyncExitStack() as exit_stack:
        FIRST_DNS_SERVER = "10.0.80.83"
        SECOND_DNS_SERVER = "10.0.80.82"

        env = await setup_mesh_nodes(
            exit_stack,
            [
                SetupParameters(
                    connection_tag=ConnectionTag.DOCKER_CONE_CLIENT_1,
                    ip_stack=IPStack.IPv4v6,
                    connection_tracker_config=generate_connection_tracker_config(
                        ConnectionTag.DOCKER_CONE_CLIENT_1,
                        derp_1_limits=(1, 1),
                    ),
                )
            ],
        )
        client_alpha = env.clients[0]
        connection_alpha = env.connections[0].connection

        await client_alpha.enable_magic_dns([FIRST_DNS_SERVER, SECOND_DNS_SERVER])
        await asyncio.sleep(1)

        await query_dns_port(
            connection_alpha,
            "53",
            "error-with-noerror-return-code.com",
            dns_server=LIBTELIO_DNS_IPV4,
        )

        await client_alpha.wait_for_log(
            "Got an error response with NoError code for error-with-noerror-return-code.com., this should not happen so converting to ServFail"
        )

        await client_alpha.wait_for_log(
            'DNS name resolution failed (no records): ResolveError { kind: NoRecordsFound { query: Query { name: Name("error-with-noerror-return-code.com."), query_type: A, query_class: IN }, soa: None, negative_ttl: None, response_code: NoError, trusted: true } }'
        )
