import asyncio
import base64
import config
import pytest
import re
import telio
import timeouts
from config import DERP_SERVERS
from contextlib import AsyncExitStack
from helpers import setup_mesh_nodes, SetupParameters
from itertools import groupby
from telio import PathType, State
from telio_features import (
    TelioFeatures,
    Direct,
    Lana,
    Nurse,
    Wireguard,
    SkipUnresponsivePeers,
    FeatureEndpointProvidersOptimization,
    PersistentKeepalive,
)
from typing import List, Tuple
from utils import testing
from utils.asyncio_util import run_async_context
from utils.connection_util import ConnectionTag
from utils.ping import Ping

ANY_PROVIDERS = ["local", "stun"]

DOCKER_CONE_GW_2_IP = "10.0.254.2"
DOCKER_FULLCONE_GW_1_IP = "10.0.254.9"
DOCKER_FULLCONE_GW_2_IP = "10.0.254.6"
DOCKER_OPEN_INTERNET_CLIENT_1_IP = "10.0.11.2"
DOCKER_OPEN_INTERNET_CLIENT_2_IP = "10.0.11.3"
DOCKER_OPEN_INTERNET_CLIENT_DUAL_STACK_IP = "10.0.11.4"
DOCKER_SYMMETRIC_CLIENT_1_IP = "192.168.103.88"
DOCKER_SYMMETRIC_GW_1_IP = "10.0.254.3"
DOCKER_UPNP_CLIENT_2_IP = "10.0.254.12"


def _generate_setup_parameter_pair(
    cfg: List[Tuple[ConnectionTag, List[str]]],
) -> List[SetupParameters]:
    return [
        SetupParameters(
            connection_tag=conn_tag,
            adapter_type=telio.AdapterType.BoringTun,
            features=TelioFeatures(
                direct=Direct(providers=endpoint_providers),
                nurse=Nurse(
                    fingerprint=f"{conn_tag}",
                    enable_nat_traversal_conn_data=True,
                    enable_nat_type_collection=True,
                ),
                lana=Lana(prod=False, event_path="/event.db"),
            ),
        )
        for conn_tag, endpoint_providers in cfg
    ]


UHP_WORKING_PATHS = [
    pytest.param(
        _generate_setup_parameter_pair([
            (ConnectionTag.DOCKER_FULLCONE_CLIENT_1, ["stun"]),
            (ConnectionTag.DOCKER_FULLCONE_CLIENT_2, ["stun"]),
        ]),
        DOCKER_FULLCONE_GW_2_IP,
    ),
    pytest.param(
        _generate_setup_parameter_pair([
            (ConnectionTag.DOCKER_SYMMETRIC_CLIENT_1, ["stun"]),
            (ConnectionTag.DOCKER_FULLCONE_CLIENT_1, ["stun"]),
        ]),
        DOCKER_FULLCONE_GW_1_IP,
    ),
    pytest.param(
        _generate_setup_parameter_pair([
            (ConnectionTag.DOCKER_OPEN_INTERNET_CLIENT_1, ["stun"]),
            (ConnectionTag.DOCKER_FULLCONE_CLIENT_1, ["stun"]),
        ]),
        DOCKER_FULLCONE_GW_1_IP,
    ),
    pytest.param(
        _generate_setup_parameter_pair([
            (ConnectionTag.DOCKER_CONE_CLIENT_1, ["stun"]),
            (ConnectionTag.DOCKER_FULLCONE_CLIENT_1, ["stun"]),
        ]),
        DOCKER_FULLCONE_GW_1_IP,
    ),
    pytest.param(
        _generate_setup_parameter_pair([
            (ConnectionTag.DOCKER_CONE_CLIENT_1, ["stun"]),
            (ConnectionTag.DOCKER_CONE_CLIENT_2, ["stun"]),
        ]),
        DOCKER_CONE_GW_2_IP,
    ),
    pytest.param(
        _generate_setup_parameter_pair([
            (ConnectionTag.DOCKER_CONE_CLIENT_1, ["stun"]),
            (ConnectionTag.DOCKER_OPEN_INTERNET_CLIENT_1, ["stun"]),
        ]),
        DOCKER_OPEN_INTERNET_CLIENT_1_IP,
    ),
    pytest.param(
        _generate_setup_parameter_pair([
            (ConnectionTag.DOCKER_OPEN_INTERNET_CLIENT_1, ["stun"]),
            (ConnectionTag.DOCKER_OPEN_INTERNET_CLIENT_2, ["stun"]),
        ]),
        DOCKER_OPEN_INTERNET_CLIENT_2_IP,
    ),
    pytest.param(
        _generate_setup_parameter_pair([
            (ConnectionTag.DOCKER_SYMMETRIC_CLIENT_1, ["stun"]),
            (ConnectionTag.DOCKER_OPEN_INTERNET_CLIENT_1, ["stun"]),
        ]),
        DOCKER_OPEN_INTERNET_CLIENT_1_IP,
    ),
    pytest.param(
        _generate_setup_parameter_pair([
            (ConnectionTag.DOCKER_UPNP_CLIENT_1, ["upnp"]),
            (ConnectionTag.DOCKER_UPNP_CLIENT_2, ["upnp"]),
        ]),
        DOCKER_UPNP_CLIENT_2_IP,
    ),
    pytest.param(
        _generate_setup_parameter_pair([
            (ConnectionTag.DOCKER_OPEN_INTERNET_CLIENT_DUAL_STACK, ["stun"]),
            (ConnectionTag.DOCKER_OPEN_INTERNET_CLIENT_2, ["stun"]),
        ]),
        DOCKER_OPEN_INTERNET_CLIENT_2_IP,
    ),
    pytest.param(
        _generate_setup_parameter_pair([
            (ConnectionTag.DOCKER_OPEN_INTERNET_CLIENT_1, ["stun"]),
            (ConnectionTag.DOCKER_OPEN_INTERNET_CLIENT_DUAL_STACK, ["stun"]),
        ]),
        DOCKER_OPEN_INTERNET_CLIENT_DUAL_STACK_IP,
    ),
    pytest.param(
        _generate_setup_parameter_pair([
            (ConnectionTag.DOCKER_SYMMETRIC_CLIENT_1, ["local"]),
            (ConnectionTag.DOCKER_OPEN_INTERNET_CLIENT_1, ["local"]),
        ]),
        DOCKER_OPEN_INTERNET_CLIENT_1_IP,
    ),
    pytest.param(
        _generate_setup_parameter_pair([
            (ConnectionTag.DOCKER_CONE_CLIENT_1, ["local"]),
            (ConnectionTag.DOCKER_OPEN_INTERNET_CLIENT_1, ["local"]),
        ]),
        DOCKER_OPEN_INTERNET_CLIENT_1_IP,
    ),
    pytest.param(
        _generate_setup_parameter_pair([
            (ConnectionTag.DOCKER_FULLCONE_CLIENT_1, ["local"]),
            (ConnectionTag.DOCKER_OPEN_INTERNET_CLIENT_1, ["local"]),
        ]),
        DOCKER_OPEN_INTERNET_CLIENT_1_IP,
    ),
    pytest.param(
        _generate_setup_parameter_pair([
            (ConnectionTag.DOCKER_INTERNAL_SYMMETRIC_CLIENT, ["local"]),
            (ConnectionTag.DOCKER_SYMMETRIC_CLIENT_1, ["local"]),
        ]),
        DOCKER_SYMMETRIC_CLIENT_1_IP,
    ),
]

UHP_FAILING_PATHS = [
    pytest.param(
        _generate_setup_parameter_pair([
            (ConnectionTag.DOCKER_CONE_CLIENT_1, ANY_PROVIDERS),
            (ConnectionTag.DOCKER_SYMMETRIC_CLIENT_1, ANY_PROVIDERS),
        ])
    ),
    pytest.param(
        _generate_setup_parameter_pair([
            (ConnectionTag.DOCKER_CONE_CLIENT_1, ANY_PROVIDERS),
            (ConnectionTag.DOCKER_UDP_BLOCK_CLIENT_1, ANY_PROVIDERS),
        ])
    ),
    pytest.param(
        _generate_setup_parameter_pair([
            (ConnectionTag.DOCKER_SYMMETRIC_CLIENT_1, ANY_PROVIDERS),
            (ConnectionTag.DOCKER_SYMMETRIC_CLIENT_2, ANY_PROVIDERS),
        ])
    ),
    pytest.param(
        _generate_setup_parameter_pair([
            (ConnectionTag.DOCKER_SYMMETRIC_CLIENT_1, ANY_PROVIDERS),
            (ConnectionTag.DOCKER_UDP_BLOCK_CLIENT_1, ANY_PROVIDERS),
        ])
    ),
    pytest.param(
        _generate_setup_parameter_pair([
            (ConnectionTag.DOCKER_OPEN_INTERNET_CLIENT_1, ANY_PROVIDERS),
            (ConnectionTag.DOCKER_UDP_BLOCK_CLIENT_1, ANY_PROVIDERS),
        ])
    ),
    pytest.param(
        _generate_setup_parameter_pair([
            (ConnectionTag.DOCKER_UDP_BLOCK_CLIENT_1, ANY_PROVIDERS),
            (ConnectionTag.DOCKER_UDP_BLOCK_CLIENT_2, ANY_PROVIDERS),
        ])
    ),
    pytest.param(
        _generate_setup_parameter_pair([
            (ConnectionTag.DOCKER_OPEN_INTERNET_CLIENT_1, ["local"]),
            (ConnectionTag.DOCKER_FULLCONE_CLIENT_1, ["local"]),
        ])
    ),
    pytest.param(
        _generate_setup_parameter_pair([
            (ConnectionTag.DOCKER_CONE_CLIENT_1, ["local"]),
            (ConnectionTag.DOCKER_OPEN_INTERNET_CLIENT_1, ["local"]),
        ])
    ),
    pytest.param(
        _generate_setup_parameter_pair([
            (ConnectionTag.DOCKER_SYMMETRIC_CLIENT_1, ["local"]),
            (ConnectionTag.DOCKER_OPEN_INTERNET_CLIENT_1, ["local"]),
        ])
    ),
]


@pytest.mark.asyncio
@pytest.mark.long
@pytest.mark.timeout(timeouts.TEST_DIRECT_FAILING_PATHS_TIMEOUT)
@pytest.mark.parametrize("setup_params", UHP_FAILING_PATHS)
# Not sure this is needed. It will only be helpful to catch if any
# libtelio change would make any of these setup work.
async def test_direct_failing_paths(setup_params: List[SetupParameters]) -> None:
    async with AsyncExitStack() as exit_stack:
        env = await setup_mesh_nodes(exit_stack, setup_params, is_timeout_expected=True)
        _, beta = env.nodes
        alpha_client, beta_client = env.clients
        alpha_connection, _ = [conn.connection for conn in env.connections]

        for server in DERP_SERVERS:
            await exit_stack.enter_async_context(
                alpha_client.get_router().break_tcp_conn_to_host(str(server["ipv4"]))
            )
            await exit_stack.enter_async_context(
                beta_client.get_router().break_tcp_conn_to_host(str(server["ipv4"]))
            )

        await asyncio.gather(
            alpha_client.wait_for_state_on_any_derp([State.Connecting]),
            beta_client.wait_for_state_on_any_derp([State.Connecting]),
        )

        with pytest.raises(asyncio.TimeoutError):
            async with Ping(alpha_connection, beta.ip_addresses[0]).run() as ping:
                await ping.wait_for_next_ping()


@pytest.mark.asyncio
@pytest.mark.parametrize("setup_params, _reflexive_ip", UHP_WORKING_PATHS)
async def test_direct_working_paths(
    setup_params: List[SetupParameters],
    _reflexive_ip: str,
) -> None:
    async with AsyncExitStack() as exit_stack:
        env = await setup_mesh_nodes(exit_stack, setup_params)
        _, beta = env.nodes
        alpha_client, beta_client = env.clients
        alpha_connection, _ = [conn.connection for conn in env.connections]

        for server in DERP_SERVERS:
            await exit_stack.enter_async_context(
                alpha_client.get_router().break_tcp_conn_to_host(str(server["ipv4"]))
            )
            await exit_stack.enter_async_context(
                beta_client.get_router().break_tcp_conn_to_host(str(server["ipv4"]))
            )

        async with Ping(alpha_connection, beta.ip_addresses[0]).run() as ping:
            await ping.wait_for_next_ping()


@pytest.mark.moose
@pytest.mark.asyncio
@pytest.mark.timeout(
    timeouts.TEST_DIRECT_WORKING_PATHS_ARE_REESTABLISHED_AND_CORRECTLY_REPORTED_IN_ANALYTICS_TIMEOUT
)
@pytest.mark.parametrize("setup_params, reflexive_ip", UHP_WORKING_PATHS)
async def test_direct_working_paths_are_reestablished_and_correctly_reported_in_analytics(
    setup_params: List[SetupParameters],
    reflexive_ip: str,
) -> None:
    async with AsyncExitStack() as exit_stack:
        env = await setup_mesh_nodes(exit_stack, setup_params)
        alpha, beta = env.nodes
        alpha_client, beta_client = env.clients

        def fix_provider_name(name):
            return "UPnP" if name == "upnp" else name.title()

        alpha_direct = alpha_client.get_features().direct
        # Asserts are here to silence mypy...
        assert alpha_direct is not None
        assert alpha_direct.providers is not None
        assert len(alpha_direct.providers) > 0
        alpha_provider = fix_provider_name(alpha_direct.providers[0])

        beta_direct = beta_client.get_features().direct
        # Asserts are here to silence mypy...
        assert beta_direct is not None
        assert beta_direct.providers is not None
        assert len(beta_direct.providers) > 0
        beta_provider = fix_provider_name(beta_direct.providers[0])

        alpha_connection, _ = [conn.connection for conn in env.connections]

        async with Ping(alpha_connection, beta.ip_addresses[0]).run() as ping:
            await ping.wait_for_next_ping()

        # Break UHP
        async with AsyncExitStack() as temp_exit_stack:
            await temp_exit_stack.enter_async_context(
                alpha_client.get_router().disable_path(reflexive_ip)
            )

            await asyncio.gather(
                alpha_client.wait_for_state_peer(
                    beta.public_key,
                    [State.Connected],
                    [PathType.Relay],
                    timeout=60.0,
                ),
                beta_client.wait_for_state_peer(
                    alpha.public_key,
                    [State.Connected],
                    [PathType.Relay],
                    timeout=60.0,
                ),
            )

            async with Ping(alpha_connection, beta.ip_addresses[0]).run() as ping:
                await ping.wait_for_next_ping()

        await asyncio.gather(
            alpha_client.wait_for_state_peer(
                beta.public_key, [State.Connected], [PathType.Direct]
            ),
            beta_client.wait_for_state_peer(
                alpha.public_key, [State.Connected], [PathType.Direct]
            ),
        )

        async with Ping(alpha_connection, beta.ip_addresses[0]).run() as ping:
            await ping.wait_for_next_ping()

        # Break UHP
        async with AsyncExitStack() as temp_exit_stack:
            await temp_exit_stack.enter_async_context(
                alpha_client.get_router().disable_path(reflexive_ip)
            )

            await asyncio.gather(
                alpha_client.wait_for_state_peer(
                    beta.public_key,
                    [State.Connected],
                    [PathType.Relay],
                    timeout=60.0,
                ),
                beta_client.wait_for_state_peer(
                    alpha.public_key,
                    [State.Connected],
                    [PathType.Relay],
                    timeout=60.0,
                ),
            )

            async with Ping(alpha_connection, beta.ip_addresses[0]).run() as ping:
                await ping.wait_for_next_ping()

        await asyncio.gather(
            alpha_client.wait_for_state_peer(
                beta.public_key, [State.Connected], [PathType.Direct]
            ),
            beta_client.wait_for_state_peer(
                alpha.public_key, [State.Connected], [PathType.Direct]
            ),
        )

        pred = ".* telio_nurse::aggregator: \\d+: (.* peer state change for .* will be reported)"
        # We need to compare the decoded forms, not the base64 encoded strings
        if base64.b64decode(alpha.public_key) < base64.b64decode(beta.public_key):
            losing_key = beta.public_key
            log_lines = await alpha_client.get_log_lines(pred)
            from_provider = alpha_provider
            to_provider = beta_provider
        else:
            losing_key = alpha.public_key
            log_lines = await beta_client.get_log_lines(pred)
            from_provider = beta_provider
            to_provider = alpha_provider
        deduplicated_lines = [l for l, _ in groupby(log_lines)]
        direct_event = f"Direct peer state change for {losing_key} to Connected ({from_provider} -> {to_provider}) will be reported"
        relayed_event = (
            f"Relayed peer state change for {losing_key} to Connected will be reported"
        )
        expected = [
            relayed_event,
            direct_event,
            relayed_event,
            direct_event,
            relayed_event,
            direct_event,
        ]
        assert expected == deduplicated_lines


@pytest.mark.asyncio
async def test_direct_working_paths_stun_ipv6() -> None:
    # This test only checks if stun works well with IPv6, no need to add more setups here
    setup_params = [
        SetupParameters(
            connection_tag=conn_tag,
            adapter_type=telio.AdapterType.BoringTun,
            features=TelioFeatures(
                direct=Direct(
                    providers=["stun"],
                ),
                ipv6=True,
            ),
        )
        for conn_tag in [
            (ConnectionTag.DOCKER_FULLCONE_CLIENT_1),
            (ConnectionTag.DOCKER_FULLCONE_CLIENT_2),
        ]
    ]
    async with AsyncExitStack() as exit_stack:
        env = await setup_mesh_nodes(exit_stack, setup_params)
        _, beta = env.nodes
        alpha_client, beta_client = env.clients
        alpha_connection, _ = [conn.connection for conn in env.connections]

        for server in DERP_SERVERS:
            await exit_stack.enter_async_context(
                alpha_client.get_router().break_tcp_conn_to_host(str(server["ipv4"]))
            )
            await exit_stack.enter_async_context(
                beta_client.get_router().break_tcp_conn_to_host(str(server["ipv4"]))
            )

        async with Ping(alpha_connection, beta.ip_addresses[0]).run() as ping:
            await ping.wait_for_next_ping()


@pytest.mark.asyncio
@pytest.mark.parametrize("setup_params, reflexive_ip", UHP_WORKING_PATHS)
async def test_direct_short_connection_loss(
    setup_params: List[SetupParameters], reflexive_ip: str
) -> None:
    async with AsyncExitStack() as exit_stack:
        env = await setup_mesh_nodes(exit_stack, setup_params)
        _, beta = env.nodes
        alpha_client, _ = env.clients
        alpha_connection, beta_connection = [
            conn.connection for conn in env.connections
        ]

        # Disrupt UHP connection
        async with AsyncExitStack() as temp_exit_stack:
            await temp_exit_stack.enter_async_context(
                alpha_client.get_router().disable_path(reflexive_ip)
            )
            # Clear conntrack to make UHP disruption faster
            await alpha_connection.create_process(["conntrack", "-F"]).execute()
            await beta_connection.create_process(["conntrack", "-F"]).execute()
            task = await temp_exit_stack.enter_async_context(
                run_async_context(
                    alpha_client.wait_for_event_peer(beta.public_key, [State.Connected])
                )
            )
            async with Ping(alpha_connection, beta.ip_addresses[0]).run() as ping:
                try:
                    await ping.wait_for_next_ping()
                except asyncio.TimeoutError:
                    pass
                else:
                    # if no timeout exception happens, this means, that peers connected through relay
                    # faster than we expected, but if no relay event occurs, this means, that something
                    # else was wrong, so we assert
                    await asyncio.wait_for(task, 1)

        async with Ping(alpha_connection, beta.ip_addresses[0]).run() as ping:
            await ping.wait_for_next_ping(60)


@pytest.mark.asyncio
@pytest.mark.long
@pytest.mark.parametrize("setup_params, reflexive_ip", UHP_WORKING_PATHS)
async def test_direct_connection_loss_for_infinity(
    setup_params: List[SetupParameters], reflexive_ip: str
) -> None:
    async with AsyncExitStack() as exit_stack:
        env = await setup_mesh_nodes(exit_stack, setup_params)
        alpha, beta = env.nodes
        alpha_client, beta_client = env.clients
        alpha_connection, _ = [conn.connection for conn in env.connections]

        # Break UHP route and wait for relay connection
        async with AsyncExitStack() as temp_exit_stack:
            await temp_exit_stack.enter_async_context(
                alpha_client.get_router().disable_path(reflexive_ip)
            )
            task = await temp_exit_stack.enter_async_context(
                run_async_context(
                    asyncio.gather(
                        alpha_client.wait_for_event_peer(
                            beta.public_key, [State.Connected]
                        ),
                        beta_client.wait_for_event_peer(
                            alpha.public_key, [State.Connected]
                        ),
                    )
                )
            )
            async with Ping(alpha_connection, beta.ip_addresses[0]).run() as ping:
                try:
                    await ping.wait_for_next_ping()
                except asyncio.TimeoutError:
                    pass
                else:
                    # if no timeout exception happens, this means, that peers connected through relay
                    # faster than we expected, but if no relay event occurs, this means, that something
                    # else was wrong, so we assert
                    await asyncio.wait_for(task, 1)

            await testing.wait_lengthy(task)

            async with Ping(alpha_connection, beta.ip_addresses[0]).run() as ping:
                await ping.wait_for_next_ping(60)


@pytest.mark.asyncio
@pytest.mark.parametrize("setup_params, _reflexive_ip", UHP_WORKING_PATHS)
async def test_direct_working_paths_with_skip_unresponsive_peers(
    setup_params: List[SetupParameters], _reflexive_ip: str
) -> None:
    async with AsyncExitStack() as exit_stack:
        # Force shorter unresponsive peer handshake threshold
        # and adjust wireguard keepalives accordingly too
        # in order to allow for three packet drops
        for param in setup_params:
            assert param.features.direct is not None
            param.features.direct.skip_unresponsive_peers = SkipUnresponsivePeers(
                no_rx_threshold_secs=16
            )
            param.features.wireguard = Wireguard(
                persistent_keepalive=PersistentKeepalive(proxying=5, direct=5)
            )

        env = await setup_mesh_nodes(exit_stack, setup_params)
        api = env.api
        alpha, beta = env.nodes
        alpha_client, beta_client = env.clients
        alpha_connection, _ = [conn.connection for conn in env.connections]

        async with Ping(alpha_connection, beta.ip_addresses[0]).run() as ping:
            await ping.wait_for_next_ping()

        await alpha_client.stop_device()

        await beta_client.wait_for_log(
            f"Skipping sending CMM to peer {alpha.public_key} (Unresponsive)"
        )

        await alpha_client.simple_start()
        await alpha_client.set_meshmap(api.get_meshmap(alpha.id))

        await asyncio.gather(
            alpha_client.wait_for_state_peer(
                beta.public_key, [State.Connected], [PathType.Direct]
            ),
            beta_client.wait_for_state_peer(
                alpha.public_key, [State.Connected], [PathType.Direct]
            ),
        )

        async with Ping(alpha_connection, beta.ip_addresses[0]).run() as ping:
            await ping.wait_for_next_ping()


@pytest.mark.timeout(timeouts.TEST_DIRECT_CONNECTION_ENDPOINT_GONE)
@pytest.mark.asyncio
@pytest.mark.parametrize(
    "setup_params",
    [
        pytest.param(
            _generate_setup_parameter_pair([
                (ConnectionTag.DOCKER_CONE_CLIENT_1, ["stun"]),
                (ConnectionTag.DOCKER_CONE_CLIENT_2, ["stun"]),
            ])
        ),
        pytest.param(
            _generate_setup_parameter_pair([
                (ConnectionTag.DOCKER_UPNP_CLIENT_1, ["upnp"]),
                (ConnectionTag.DOCKER_UPNP_CLIENT_2, ["upnp"]),
            ])
        ),
        pytest.param(
            _generate_setup_parameter_pair([
                (ConnectionTag.DOCKER_UPNP_CLIENT_1, ["upnp"]),
                (ConnectionTag.DOCKER_CONE_CLIENT_2, ["stun"]),
            ])
        ),
        pytest.param(
            _generate_setup_parameter_pair([
                (ConnectionTag.DOCKER_UPNP_CLIENT_1, ["upnp"]),
                (ConnectionTag.DOCKER_OPEN_INTERNET_CLIENT_1, ["local"]),
            ])
        ),
        pytest.param(
            _generate_setup_parameter_pair([
                (ConnectionTag.DOCKER_CONE_CLIENT_1, ["stun"]),
                (ConnectionTag.DOCKER_OPEN_INTERNET_CLIENT_1, ["local"]),
            ])
        ),
    ],
)
async def test_direct_connection_endpoint_gone(
    setup_params: List[SetupParameters],
) -> None:
    async with AsyncExitStack() as exit_stack:
        env = await setup_mesh_nodes(exit_stack, setup_params)
        alpha, beta = env.nodes
        alpha_client, beta_client = env.clients
        alpha_connection, _ = [conn.connection for conn in env.connections]

        async def _check_if_true_direct_connection() -> None:
            async with AsyncExitStack() as temp_exit_stack:
                for derp in DERP_SERVERS:
                    await temp_exit_stack.enter_async_context(
                        alpha_client.get_router().break_tcp_conn_to_host(
                            str(derp["ipv4"])
                        )
                    )
                    await temp_exit_stack.enter_async_context(
                        beta_client.get_router().break_tcp_conn_to_host(
                            str(derp["ipv4"])
                        )
                    )

                await asyncio.gather(
                    alpha_client.wait_for_state_on_any_derp(
                        [State.Connecting, State.Disconnected]
                    ),
                    beta_client.wait_for_state_on_any_derp(
                        [State.Connecting, State.Disconnected]
                    ),
                )

                async with Ping(alpha_connection, beta.ip_addresses[0]).run() as ping:
                    await ping.wait_for_next_ping(60)

        await _check_if_true_direct_connection()

        await asyncio.gather(
            alpha_client.wait_for_state_on_any_derp([State.Connected]),
            beta_client.wait_for_state_on_any_derp([State.Connected]),
        )

        async with AsyncExitStack() as temp_exit_stack:
            await temp_exit_stack.enter_async_context(
                alpha_client.get_router().disable_path(
                    alpha_client.get_endpoint_address(beta.public_key)
                )
            )
            await temp_exit_stack.enter_async_context(
                beta_client.get_router().disable_path(
                    beta_client.get_endpoint_address(alpha.public_key)
                )
            )

            await asyncio.gather(
                alpha_client.wait_for_state_peer(beta.public_key, [State.Connected]),
                beta_client.wait_for_state_peer(alpha.public_key, [State.Connected]),
            )

            async with Ping(alpha_connection, beta.ip_addresses[0]).run() as ping:
                await ping.wait_for_next_ping(60)

        await asyncio.gather(
            alpha_client.wait_for_state_peer(
                beta.public_key, [State.Connected], [PathType.Direct]
            ),
            beta_client.wait_for_state_peer(
                alpha.public_key, [State.Connected], [PathType.Direct]
            ),
        )

        await _check_if_true_direct_connection()


@pytest.mark.asyncio
# Regression test for LLT-4306
@pytest.mark.parametrize(
    "setup_params",
    [
        pytest.param(
            _generate_setup_parameter_pair(
                [
                    (ConnectionTag.DOCKER_CONE_CLIENT_1, ["stun"]),
                    (ConnectionTag.DOCKER_CONE_CLIENT_2, ["stun"]),
                ],
            )
        )
    ],
)
async def test_infinite_stun_loop(setup_params: List[SetupParameters]) -> None:
    async with AsyncExitStack() as exit_stack:
        env = await setup_mesh_nodes(exit_stack, setup_params)
        alpha_client, _ = env.clients
        alpha_connection, _ = [conn.connection for conn in env.connections]

        for server in config.DERP_SERVERS:
            await exit_stack.enter_async_context(
                alpha_client.get_router().break_udp_conn_to_host(str(server["ipv4"]))
            )

        # 3478 and 3479 are STUN ports in natlab containers
        tcpdump = await exit_stack.enter_async_context(
            alpha_connection.create_process([
                "tcpdump",
                "--immediate-mode",
                "-l",
                "-i",
                "any",
                "(",
                "port",
                "3478",
                "or",
                "3479",
                ")",
            ]).run()
        )
        await asyncio.sleep(5)

        stun_requests = tcpdump.get_stdout().splitlines()
        # There seems to be some delay when getting stdout from a process
        # Without this delay, `stun_requests` is empty even if tcpdump reports traffic
        await asyncio.sleep(0.5)
        # 20 is a semi-random number that is low enough to prove the original issue is not present
        # while being high enough to prevent false-positivies.
        # The actual number of requests will be lower given the time frame that is being measured.
        assert len(stun_requests) < 20


@pytest.mark.asyncio
@pytest.mark.parametrize("setup_params, _reflexive_ip", UHP_WORKING_PATHS)
async def test_direct_working_paths_with_pausing_upnp_and_stun(
    setup_params: List[SetupParameters], _reflexive_ip: str
) -> None:
    async with AsyncExitStack() as exit_stack:
        stun_enabled = False
        upnp_enabled = False
        for param in setup_params:
            assert param.features.direct is not None
            param.features.direct.endpoint_providers_optimization = (
                FeatureEndpointProvidersOptimization(
                    optimize_direct_upgrade_stun=True,
                    optimize_direct_upgrade_upnp=True,
                )
            )

            if (
                param.features.direct.providers is not None
                and "stun" in param.features.direct.providers
            ):
                stun_enabled = True

            if (
                param.features.direct.providers is not None
                and "upnp" in param.features.direct.providers
            ):
                upnp_enabled = True

        env = await setup_mesh_nodes(exit_stack, setup_params)
        _, beta = env.nodes
        alpha_client, _ = env.clients
        alpha_connection, _ = [conn.connection for conn in env.connections]

        async with Ping(alpha_connection, beta.ip_addresses[0]).run() as ping:
            await ping.wait_for_next_ping()

        # wait for upnp and stun to be paused
        await asyncio.sleep(5)

        if stun_enabled:
            await testing.wait_long(
                alpha_client.wait_for_log(
                    "Skipping getting endpoint via STUN endpoint provider(ModulePaused)"
                )
            )
        if upnp_enabled:
            await testing.wait_long(
                alpha_client.wait_for_log(
                    "Skipping getting endpoint via UPNP endpoint provider(ModulePaused)"
                )
            )

        tcpdump = await exit_stack.enter_async_context(
            alpha_connection.create_process([
                "tcpdump",
                "--immediate-mode",
                "-l",
                "-i",
                "any",
            ]).run()
        )
        await asyncio.sleep(5)

        packets = tcpdump.get_stdout().splitlines()
        # There seems to be some delay when getting stdout from a process
        # Without this delay, `stun_requests` is empty even if tcpdump reports traffic
        await asyncio.sleep(0.5)

        # filter outgoing stun packets by ports 3478/3479
        # filter upnp igd request packets by ip (ssdp multicast ip)
        # use regex with a few more symbols to avoid false positives
        match_pattern = r"\.347[89]:|239\.255\.255\.250"

        stun_upnp_requests = [
            request
            for request in packets
            if re.search(match_pattern, request) is not None
        ]

        assert len(stun_upnp_requests) == 0
