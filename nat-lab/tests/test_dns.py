# pylint: disable=too-many-lines

import asyncio
import config
import pytest
import re
from contextlib import AsyncExitStack
from helpers import SetupParameters, setup_api, setup_environment, setup_mesh_nodes
from telio import AdapterType, TelioFeatures
from utils import testing
from utils.connection_tracker import ConnectionLimits
from utils.connection_util import ConnectionTag, generate_connection_tracker_config
from utils.process import ProcessExecError
from utils.router import IPStack


def get_dns_server_address(ip_stack: IPStack) -> str:
    return (
        config.LIBTELIO_DNS_IPV4
        if ip_stack in [IPStack.IPv4, IPStack.IPv4v6]
        else config.LIBTELIO_DNS_IPV6
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
            config.LIBTELIO_DNS_IPV4
            if beta_ip_stack == IPStack.IPv4
            else config.LIBTELIO_DNS_IPV6
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
        with pytest.raises(asyncio.TimeoutError):
            await testing.wait_long(
                connection_alpha.create_process(
                    ["nslookup", "google.com", dns_server_address_alpha]
                ).execute()
            )

        with pytest.raises(asyncio.TimeoutError):
            await testing.wait_long(
                connection_beta.create_process(
                    ["nslookup", "google.com", dns_server_address_beta]
                ).execute()
            )

        await client_alpha.enable_magic_dns(["1.1.1.1"])
        await client_beta.enable_magic_dns(["1.1.1.1"])

        # If everything went correctly, these calls should not timeout
        await testing.wait_long(
            connection_alpha.create_process(
                ["nslookup", "google.com", dns_server_address_alpha]
            ).execute()
        )
        await testing.wait_long(
            connection_beta.create_process(
                ["nslookup", "google.com", dns_server_address_beta]
            ).execute()
        )

        # If the previous calls didn't fail, we can assume that the resolver is running so no need to wait for the timeout and test the validity of the response
        alpha_response = await testing.wait_long(
            connection_alpha.create_process(
                ["nslookup", "beta.nord", dns_server_address_alpha]
            ).execute()
        )
        for ip in beta.ip_addresses:
            assert ip in alpha_response.get_stdout()

        beta_response = await testing.wait_long(
            connection_beta.create_process(
                ["nslookup", "alpha.nord", dns_server_address_beta]
            ).execute()
        )
        for ip in alpha.ip_addresses:
            assert ip in beta_response.get_stdout()

        # Testing if instance can get the IP of self from DNS. See LLT-4246 for more details.
        alpha_response = await testing.wait_long(
            connection_alpha.create_process(
                ["nslookup", "alpha.nord", dns_server_address_alpha]
            ).execute()
        )
        for ip in alpha.ip_addresses:
            assert ip in alpha_response.get_stdout()

        # Now we disable magic dns
        await client_alpha.disable_magic_dns()
        await client_beta.disable_magic_dns()

        # And as a result these calls should timeout again
        with pytest.raises(asyncio.TimeoutError):
            await testing.wait_long(
                connection_alpha.create_process(
                    ["nslookup", "google.com", dns_server_address_alpha]
                ).execute()
            )
        with pytest.raises(asyncio.TimeoutError):
            await testing.wait_long(
                connection_beta.create_process(
                    ["nslookup", "google.com", dns_server_address_beta]
                ).execute()
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
@pytest.mark.xfail(reason="Test is flaky - LLT-4656")
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
        with pytest.raises(asyncio.TimeoutError):
            await testing.wait_normal(
                connection_alpha.create_process(
                    ["dig", "@" + dns_server_address_alpha, "-p", "53", "google.com"]
                ).execute()
            )

        await client_alpha.enable_magic_dns(["1.1.1.1"])
        await client_beta.enable_magic_dns(["1.1.1.1"])

        # A DNS request on port 53 should work
        await testing.wait_normal(
            connection_alpha.create_process(
                ["dig", "@" + dns_server_address_alpha, "-p", "53", "google.com"]
            ).execute()
        )

        # A DNS request on a different port should timeout
        with pytest.raises(asyncio.TimeoutError):
            await testing.wait_normal(
                connection_alpha.create_process(
                    ["dig", "@" + dns_server_address_alpha, "-p", "54", "google.com"]
                ).execute()
            )

        # Look for beta on 53 port should work
        alpha_response = await testing.wait_normal(
            connection_alpha.create_process(
                [
                    "dig",
                    "@" + dns_server_address_alpha,
                    "-p",
                    "53",
                    "beta.nord",
                    "A",
                    "beta.nord",
                    "AAAA",
                ]
            ).execute()
        )
        for ip in beta.ip_addresses:
            assert ip in alpha_response.get_stdout()

        # Look for beta on a different port should timeout
        with pytest.raises(asyncio.TimeoutError):
            await testing.wait_normal(
                connection_alpha.create_process(
                    ["dig", "@" + dns_server_address_alpha, "-p", "54", "beta.nord"]
                ).execute()
            )

        # Disable magic dns
        await client_alpha.disable_magic_dns()
        await client_beta.disable_magic_dns()

        # And as a result these calls should timeout again
        with pytest.raises(asyncio.TimeoutError):
            await testing.wait_normal(
                connection_alpha.create_process(
                    ["dig", "@" + dns_server_address_alpha, "-p", "53", "google.com"]
                ).execute()
            )

        with pytest.raises(asyncio.TimeoutError):
            await testing.wait_normal(
                connection_alpha.create_process(
                    ["dig", "@" + dns_server_address_alpha, "-p", "53", "beta.nord"]
                ).execute()
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
        await client_alpha.enable_magic_dns(["1.1.1.1"])

        # Test to see if the module is working correctly
        await testing.wait_normal(
            connection.create_process(
                ["nslookup", "google.com", dns_server_address]
            ).execute()
        )

        # Test if the DNS module preserves CNAME records
        dns_response = await testing.wait_normal(
            connection.create_process(
                ["nslookup", "-q=CNAME", "www.microsoft.com", dns_server_address]
            ).execute()
        )
        assert "canonical name" in dns_response.get_stdout()

        # Turn off the module and see if it worked
        await client_alpha.disable_magic_dns()

        with pytest.raises(asyncio.TimeoutError):
            await testing.wait_normal(
                connection.create_process(
                    ["nslookup", "google.com", dns_server_address]
                ).execute()
            )

        # Test interop with meshnet
        await client_alpha.enable_magic_dns(["1.1.1.1"])

        await client_alpha.set_meshmap(api.get_meshmap(alpha.id, derp_servers=[]))

        await testing.wait_normal(
            connection.create_process(
                ["nslookup", "google.com", dns_server_address]
            ).execute()
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
        with pytest.raises(asyncio.TimeoutError):
            await testing.wait_normal(
                connection_alpha.create_process(
                    ["nslookup", "google.com", dns_server_address]
                ).execute()
            )

        await client_alpha.enable_magic_dns(["1.1.1.1"])

        # If everything went correctly, these calls should not timeout
        await testing.wait_normal(
            connection_alpha.create_process(
                ["nslookup", "google.com", dns_server_address]
            ).execute()
        )

        # If the previous calls didn't fail, we can assume that the resolver is running so no need to wait for the timeout and test the validity of the response
        alpha_response = await testing.wait_normal(
            connection_alpha.create_process(
                ["nslookup", "beta.nord", dns_server_address]
            ).execute()
        )
        for ip in beta.ip_addresses:
            assert ip in alpha_response.get_stdout()

        # Now we disable magic dns
        await client_alpha.set_mesh_off()

        # If everything went correctly, these calls should not timeout
        await testing.wait_normal(
            connection_alpha.create_process(
                ["nslookup", "google.com", dns_server_address]
            ).execute()
        )

        # After mesh off, .nord names should not be resolved anymore, therefore nslookup should fail
        try:
            await testing.wait_normal(
                connection_alpha.create_process(
                    ["nslookup", "beta.nord", dns_server_address]
                ).execute()
            )
        except ProcessExecError as e:
            assert "server can't find beta.nord" in e.stdout


@pytest.mark.asyncio
@pytest.mark.long
@pytest.mark.timeout(60 * 5 + 60)
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

        await client_alpha.enable_magic_dns(["1.1.1.1"])
        await client_beta.enable_magic_dns(["1.1.1.1"])

        await testing.wait_normal(
            connection_alpha.create_process(
                ["nslookup", "google.com", dns_server_address]
            ).execute()
        )

        await testing.wait_normal(
            connection_beta.create_process(
                ["nslookup", "google.com", dns_server_address]
            ).execute()
        )

        alpha_response = await testing.wait_normal(
            connection_alpha.create_process(
                ["nslookup", "beta.nord", dns_server_address]
            ).execute()
        )
        for ip in beta.ip_addresses:
            assert ip in alpha_response.get_stdout()

        beta_response = await testing.wait_normal(
            connection_beta.create_process(
                ["nslookup", "alpha.nord", dns_server_address]
            ).execute()
        )
        for ip in alpha.ip_addresses:
            assert ip in beta_response.get_stdout()

        await asyncio.sleep(60 * 5)

        await testing.wait_normal(
            connection_alpha.create_process(
                ["nslookup", "google.com", dns_server_address]
            ).execute()
        )

        await testing.wait_normal(
            connection_beta.create_process(
                ["nslookup", "google.com", dns_server_address]
            ).execute()
        )

        alpha_response = await testing.wait_normal(
            connection_alpha.create_process(
                ["nslookup", "beta.nord", dns_server_address]
            ).execute()
        )
        for ip in beta.ip_addresses:
            assert ip in alpha_response.get_stdout()

        beta_response = await testing.wait_normal(
            connection_beta.create_process(
                ["nslookup", "alpha.nord", dns_server_address]
            ).execute()
        )
        for ip in alpha.ip_addresses:
            assert ip in beta_response.get_stdout()


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
            await testing.wait_normal(
                connection_alpha.create_process(
                    ["nslookup", "beta.nord", dns_server_address]
                ).execute()
            )
        except ProcessExecError as e:
            assert "server can't find beta.nord" in e.stdout

        beta = api.default_config_one_node(ip_stack=IPStack.IPv4v6)

        # Check if setting meshnet updates nord names for dns resolver
        await client_alpha.set_meshmap(api.get_meshmap(alpha.id, derp_servers=[]))

        alpha_response = await testing.wait_normal(
            connection_alpha.create_process(
                ["nslookup", "beta.nord", dns_server_address]
            ).execute()
        )
        assert beta.ip_addresses[0] in alpha_response.get_stdout()


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

        with pytest.raises(asyncio.TimeoutError):
            await testing.wait_normal(
                connection.create_process(
                    ["nslookup", "google.com", dns_server_address]
                ).execute()
            )

        # Update forward dns and check if it works now
        await client_alpha.enable_magic_dns(["1.1.1.1"])

        alpha_response = await testing.wait_normal(
            connection.create_process(
                ["nslookup", "google.com", dns_server_address]
            ).execute()
        )
        # Check if some address was found
        assert "Name:	google.com\nAddress:" in alpha_response.get_stdout()


@pytest.mark.asyncio
@pytest.mark.xfail(reason="Test is flaky - LLT-4563")
async def test_dns_duplicate_requests_on_multiple_forward_servers() -> None:
    async with AsyncExitStack() as exit_stack:
        FIRST_DNS_SERVER = "8.8.8.8"
        SECOND_DNS_SERVER = "1.1.1.1"
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
            connection_alpha.create_process(
                [
                    "tcpdump",
                    "--immediate-mode",
                    "-ni",
                    "eth0",
                    "udp",
                    "and",
                    "port",
                    "53",
                    "-l",
                ]
            ).run()
        )
        await asyncio.sleep(1)

        await client_alpha.enable_magic_dns([FIRST_DNS_SERVER, SECOND_DNS_SERVER])
        await asyncio.sleep(1)

        await testing.wait_long(
            connection_alpha.create_process(
                ["nslookup", "google.com", config.LIBTELIO_DNS_IPV4]
            ).execute()
        )
        await asyncio.sleep(1)

        tcpdump_stdout = process.get_stdout()
        results = set(re.findall(
            r".* IP .* > (?P<dest_ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\.\d{1,5}: .* A\?.*",
            tcpdump_stdout,
        ))  # fmt: skip

        assert results in ({FIRST_DNS_SERVER}, {SECOND_DNS_SERVER}), tcpdump_stdout


@pytest.mark.asyncio
async def test_dns_aaaa_records() -> None:
    async with AsyncExitStack() as exit_stack:
        api, (_, beta) = setup_api([(False, IPStack.IPv4v6), (False, IPStack.IPv4v6)])
        env = await exit_stack.enter_async_context(
            setup_environment(exit_stack, [SetupParameters()], provided_api=api)
        )
        connection_alpha, *_ = [conn.connection for conn in env.connections]
        client_alpha, *_ = env.clients

        await client_alpha.enable_magic_dns(["1.1.1.1"])

        alpha_response = await testing.wait_long(
            connection_alpha.create_process(
                ["nslookup", "beta.nord", config.LIBTELIO_DNS_IPV4]
            ).execute()
        )

        assert beta.ip_addresses[0] in alpha_response.get_stdout()
        assert beta.ip_addresses[1] in alpha_response.get_stdout()


@pytest.mark.asyncio
async def test_dns_nickname() -> None:
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

        alpha_response = await testing.wait_long(
            connection_alpha.create_process(
                ["nslookup", "yoko.nord", config.LIBTELIO_DNS_IPV4]
            ).execute()
        )
        for ip in beta.ip_addresses:
            assert ip in alpha_response.get_stdout()

        alpha_response = await testing.wait_long(
            connection_alpha.create_process(
                ["nslookup", "johnny.nord", config.LIBTELIO_DNS_IPV4]
            ).execute()
        )
        for ip in alpha.ip_addresses:
            assert ip in alpha_response.get_stdout()

        beta_response = await testing.wait_long(
            connection_beta.create_process(
                ["nslookup", "johnny.nord", config.LIBTELIO_DNS_IPV4]
            ).execute()
        )
        for ip in alpha.ip_addresses:
            assert ip in beta_response.get_stdout()

        beta_response = await testing.wait_long(
            connection_beta.create_process(
                ["nslookup", "yoko.nord", config.LIBTELIO_DNS_IPV4]
            ).execute()
        )
        for ip in beta.ip_addresses:
            assert ip in beta_response.get_stdout()


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
        api.assign_nickname(alpha.id, "rotten")
        api.assign_nickname(beta.id, "ono")
        await client_alpha.set_meshmap(api.get_meshmap(alpha.id, derp_servers=[]))
        await client_beta.set_meshmap(api.get_meshmap(beta.id, derp_servers=[]))

        alpha_response = await testing.wait_long(
            connection_alpha.create_process(
                ["nslookup", "ono.nord", config.LIBTELIO_DNS_IPV4]
            ).execute()
        )
        for ip in beta.ip_addresses:
            assert ip in alpha_response.get_stdout()

        alpha_response = await testing.wait_long(
            connection_alpha.create_process(
                ["nslookup", "rotten.nord", config.LIBTELIO_DNS_IPV4]
            ).execute()
        )
        for ip in alpha.ip_addresses:
            assert ip in alpha_response.get_stdout()

        beta_response = await testing.wait_long(
            connection_beta.create_process(
                ["nslookup", "rotten.nord", config.LIBTELIO_DNS_IPV4]
            ).execute()
        )
        for ip in alpha.ip_addresses:
            assert ip in beta_response.get_stdout()

        beta_response = await testing.wait_long(
            connection_beta.create_process(
                ["nslookup", "ono.nord", config.LIBTELIO_DNS_IPV4]
            ).execute()
        )
        for ip in beta.ip_addresses:
            assert ip in beta_response.get_stdout()

        api.reset_nickname(alpha.id)
        api.reset_nickname(beta.id)
        await client_alpha.set_meshmap(api.get_meshmap(alpha.id, derp_servers=[]))
        await client_beta.set_meshmap(api.get_meshmap(beta.id, derp_servers=[]))

        with pytest.raises(ProcessExecError):
            alpha_response = await testing.wait_long(
                connection_alpha.create_process(
                    ["nslookup", "ono.nord", config.LIBTELIO_DNS_IPV4]
                ).execute()
            )

        with pytest.raises(ProcessExecError):
            alpha_response = await testing.wait_long(
                connection_alpha.create_process(
                    ["nslookup", "rotten.nord", config.LIBTELIO_DNS_IPV4]
                ).execute()
            )

        with pytest.raises(ProcessExecError):
            beta_response = await testing.wait_long(
                connection_beta.create_process(
                    ["nslookup", "rotten.nord", config.LIBTELIO_DNS_IPV4]
                ).execute()
            )

        with pytest.raises(ProcessExecError):
            beta_response = await testing.wait_long(
                connection_beta.create_process(
                    ["nslookup", "ono.nord", config.LIBTELIO_DNS_IPV4]
                ).execute()
            )
