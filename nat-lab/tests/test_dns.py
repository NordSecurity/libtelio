# pylint: disable=too-many-lines

import asyncio
import config
import itertools
import pytest
import re
import timeouts
from config import LIBTELIO_DNS_IPV4, LIBTELIO_DNS_IPV6
from contextlib import AsyncExitStack
from helpers import SetupParameters, setup_api, setup_environment, setup_mesh_nodes
from telio import AdapterType, TelioFeatures
from telio_features import Dns
from typing import List
from utils.connection_tracker import ConnectionLimits
from utils.connection_util import ConnectionTag, generate_connection_tracker_config
from utils.dns import query_dns, query_dns_port
from utils.process import ProcessExecError
from utils.router import IPStack


def get_dns_server_address(ip_stack: IPStack) -> str:
    return (
        LIBTELIO_DNS_IPV4
        if ip_stack in [IPStack.IPv4, IPStack.IPv4v6]
        else LIBTELIO_DNS_IPV6
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
                SetupParameters(
                    connection_tag=ConnectionTag.DOCKER_CONE_CLIENT_1,
                    connection_tracker_config=generate_connection_tracker_config(
                        ConnectionTag.DOCKER_CONE_CLIENT_1,
                        derp_1_limits=ConnectionLimits(1, 1),
                    ),
                ),
                SetupParameters(
                    connection_tag=ConnectionTag.DOCKER_CONE_CLIENT_2,
                    connection_tracker_config=generate_connection_tracker_config(
                        ConnectionTag.DOCKER_CONE_CLIENT_2,
                        derp_1_limits=ConnectionLimits(1, 1),
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
            connection_alpha, "beta.nord", beta.ip_addresses, dns_server_address_alpha
        )
        await query_dns(
            connection_beta, "alpha.nord", alpha.ip_addresses, dns_server_address_beta
        )

        # Testing if instance can get the IP of self from DNS. See LLT-4246 for more details.
        await query_dns(
            connection_alpha, "alpha.nord", alpha.ip_addresses, dns_server_address_alpha
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
async def test_dns_port(alpha_ip_stack: IPStack) -> None:
    async with AsyncExitStack() as exit_stack:
        dns_server_address_alpha = get_dns_server_address(alpha_ip_stack)
        env = await setup_mesh_nodes(
            exit_stack,
            [
                SetupParameters(
                    connection_tag=ConnectionTag.DOCKER_CONE_CLIENT_1,
                    ip_stack=alpha_ip_stack,
                    connection_tracker_config=generate_connection_tracker_config(
                        ConnectionTag.DOCKER_CONE_CLIENT_1,
                        derp_1_limits=ConnectionLimits(1, 1),
                    ),
                ),
                SetupParameters(
                    connection_tag=ConnectionTag.DOCKER_CONE_CLIENT_2,
                    ip_stack=IPStack.IPv4v6,
                    connection_tracker_config=generate_connection_tracker_config(
                        ConnectionTag.DOCKER_CONE_CLIENT_2,
                        derp_1_limits=ConnectionLimits(1, 1),
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
            beta.ip_addresses,
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
                            vpn_1_limits=ConnectionLimits(1, 1),
                        ),
                        is_meshnet=False,
                    )
                ],
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
            "-q=CNAME",
        )

        # Turn off the module and see if it worked
        await client_alpha.disable_magic_dns()

        with pytest.raises(ProcessExecError):
            await query_dns(connection, "google.com", dns_server=dns_server_address)

        # Test interop with meshnet
        await client_alpha.enable_magic_dns(["10.0.80.82"])
        await client_alpha.set_meshmap(api.get_meshmap(alpha.id, derp_servers=[]))

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
                        features=TelioFeatures(ipv6=True),
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
            connection_alpha, "beta.nord", beta.ip_addresses, dns_server_address
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
                    adapter_type=AdapterType.BoringTun,
                    connection_tracker_config=generate_connection_tracker_config(
                        ConnectionTag.DOCKER_CONE_CLIENT_1,
                        derp_1_limits=ConnectionLimits(1, 1),
                    ),
                ),
                SetupParameters(
                    connection_tag=ConnectionTag.DOCKER_CONE_CLIENT_2,
                    ip_stack=IPStack.IPv4v6,
                    connection_tracker_config=generate_connection_tracker_config(
                        ConnectionTag.DOCKER_CONE_CLIENT_2,
                        derp_1_limits=ConnectionLimits(1, 1),
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
            connection_alpha, "beta.nord", beta.ip_addresses, dns_server_address
        )
        await query_dns(
            connection_beta, "alpha.nord", alpha.ip_addresses, dns_server_address
        )

        await asyncio.sleep(60 * 5)

        await query_dns(connection_alpha, "google.com", dns_server=dns_server_address)
        await query_dns(connection_beta, "google.com", dns_server=dns_server_address)

        await query_dns(
            connection_alpha, "beta.nord", beta.ip_addresses, dns_server_address
        )
        await query_dns(
            connection_beta, "alpha.nord", alpha.ip_addresses, dns_server_address
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
async def test_set_meshmap_dns_update(
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
        await client_alpha.set_meshmap(api.get_meshmap(alpha.id, derp_servers=[]))

        await query_dns(
            connection_alpha, "beta.nord", [beta.ip_addresses[0]], dns_server_address
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
                            vpn_1_limits=ConnectionLimits(1, 1),
                        ),
                        is_meshnet=False,
                    )
                ],
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


@pytest.mark.asyncio
async def test_dns_duplicate_requests_on_multiple_forward_servers() -> None:
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
                        ConnectionTag.DOCKER_CONE_CLIENT_1
                    ),
                    derp_servers=[],
                )
            ],
        )
        connection_alpha, *_ = [conn.connection for conn in env.connections]
        client_alpha, *_ = env.clients

        process = await exit_stack.enter_async_context(
            connection_alpha.create_process([
                "tcpdump",
                "--immediate-mode",
                "-ni",
                "eth0",
                "udp",
                "and",
                "port",
                "53",
                "-l",
            ]).run()
        )
        await asyncio.sleep(1)

        await client_alpha.enable_magic_dns([FIRST_DNS_SERVER, SECOND_DNS_SERVER])
        await asyncio.sleep(1)

        await query_dns(connection_alpha, "google.com")
        await asyncio.sleep(1)

        tcpdump_stdout = process.get_stdout()
        tcpdump_stderr = process.get_stderr()
        results = set(re.findall(
            r".* IP .* > (?P<dest_ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\.\d{1,5}: .* A\?.*",
            tcpdump_stdout,
        ))  # fmt: skip

        assert results in (
            {FIRST_DNS_SERVER},
            {SECOND_DNS_SERVER},
        ), f"tcpdump stdout:\n{tcpdump_stdout}\ntcpdump stderr:\n{tcpdump_stderr}"


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

        await query_dns(connection_alpha, "beta.nord", beta.ip_addresses)


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
                        derp_1_limits=ConnectionLimits(1, 1),
                    ),
                    features=TelioFeatures(nicknames=True),
                ),
                SetupParameters(
                    connection_tag=ConnectionTag.DOCKER_CONE_CLIENT_2,
                    connection_tracker_config=generate_connection_tracker_config(
                        ConnectionTag.DOCKER_CONE_CLIENT_2,
                        derp_1_limits=ConnectionLimits(1, 1),
                    ),
                    features=TelioFeatures(nicknames=True),
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

        await query_dns(connection_alpha, "yoko.nord", beta.ip_addresses)
        await query_dns(connection_alpha, "johnny.nord", alpha.ip_addresses)

        await query_dns(connection_beta, "johnny.nord", alpha.ip_addresses)
        await query_dns(connection_beta, "yOKo.nord", beta.ip_addresses)


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
                        derp_1_limits=ConnectionLimits(1, 1),
                    ),
                    features=TelioFeatures(nicknames=True),
                ),
                SetupParameters(
                    connection_tag=ConnectionTag.DOCKER_CONE_CLIENT_2,
                    connection_tracker_config=generate_connection_tracker_config(
                        ConnectionTag.DOCKER_CONE_CLIENT_2,
                        derp_1_limits=ConnectionLimits(1, 1),
                    ),
                    features=TelioFeatures(nicknames=True),
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

        # Set new meshmap with different nicknames
        api.assign_nickname(alpha.id, "rotten")
        api.assign_nickname(beta.id, "ono")
        await client_alpha.set_meshmap(api.get_meshmap(alpha.id, derp_servers=[]))
        await client_beta.set_meshmap(api.get_meshmap(beta.id, derp_servers=[]))

        with pytest.raises(ProcessExecError):
            await query_dns(connection_alpha, "yoko.nord")
        with pytest.raises(ProcessExecError):
            await query_dns(connection_alpha, "johnny.nord")
        with pytest.raises(ProcessExecError):
            await query_dns(connection_beta, "yoko.nord")
        with pytest.raises(ProcessExecError):
            await query_dns(connection_beta, "johnny.nord")

        await query_dns(connection_alpha, "ono.nord", beta.ip_addresses)
        await query_dns(connection_alpha, "rotten.nord", alpha.ip_addresses)

        await query_dns(connection_beta, "rotten.nord", alpha.ip_addresses)
        await query_dns(connection_beta, "ono.nord", beta.ip_addresses)

        # Set new meshmap removing nicknames
        api.reset_nickname(alpha.id)
        api.reset_nickname(beta.id)
        await client_alpha.set_meshmap(api.get_meshmap(alpha.id, derp_servers=[]))
        await client_beta.set_meshmap(api.get_meshmap(beta.id, derp_servers=[]))

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
                        derp_1_limits=ConnectionLimits(1, 1),
                    ),
                    features=TelioFeatures(nicknames=True),
                ),
                SetupParameters(
                    connection_tag=ConnectionTag.DOCKER_CONE_CLIENT_2,
                    connection_tracker_config=generate_connection_tracker_config(
                        ConnectionTag.DOCKER_CONE_CLIENT_2,
                        derp_1_limits=ConnectionLimits(1, 1),
                    ),
                    features=TelioFeatures(nicknames=True),
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

        await query_dns(connection_alpha, "myserviceA.alpha.nord", alpha.ip_addresses)
        await query_dns(connection_alpha, "myserviceB.johnny.nord", alpha.ip_addresses)
        await query_dns(connection_alpha, "herservice.yoko.nord", beta.ip_addresses)

        await query_dns(connection_beta, "myserviceC.beta.nord", beta.ip_addresses)
        await query_dns(connection_beta, "myserviceD.yoko.nord", beta.ip_addresses)
        await query_dns(connection_beta, "hisservice.johnny.nord", alpha.ip_addresses)


@pytest.mark.asyncio
async def test_dns_ttl_value() -> None:
    async with AsyncExitStack() as exit_stack:
        FIRST_DNS_SERVER = "10.0.80.83"
        SECOND_DNS_SERVER = "10.0.80.82"

        EXPECTED_TTL_VALUE = 1234

        api, (_, _) = setup_api([(False, IPStack.IPv4v6), (False, IPStack.IPv4v6)])
        env = await setup_mesh_nodes(
            exit_stack,
            [
                SetupParameters(
                    connection_tag=ConnectionTag.DOCKER_CONE_CLIENT_1,
                    connection_tracker_config=generate_connection_tracker_config(
                        ConnectionTag.DOCKER_CONE_CLIENT_1,
                        derp_1_limits=ConnectionLimits(1, 1),
                    ),
                    features=TelioFeatures(
                        dns=Dns(exit_dns=None, ttl_value=EXPECTED_TTL_VALUE)
                    ),
                ),
                SetupParameters(
                    connection_tag=ConnectionTag.DOCKER_CONE_CLIENT_2,
                    connection_tracker_config=generate_connection_tracker_config(
                        ConnectionTag.DOCKER_CONE_CLIENT_2,
                        derp_1_limits=ConnectionLimits(1, 1),
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
            setup_environment(exit_stack, [SetupParameters()], provided_api=api)
        )
        connection_alpha, *_ = [conn.connection for conn in env.connections]
        client_alpha, *_ = env.clients

        await client_alpha.enable_magic_dns([])

        queries = [
            query_dns(connection_alpha, f"{name}.nord", beta.ip_addresses)
            for name in all_cases("yoko")
        ]

        asyncio.gather(*queries)


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
                        derp_1_limits=ConnectionLimits(1, 1),
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
