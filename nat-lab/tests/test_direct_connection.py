import asyncio
import config
import pytest
import telio
from config import DERP_SERVERS
from contextlib import AsyncExitStack
from helpers import setup_mesh_nodes, SetupParameters
from telio import PathType, State
from telio_features import TelioFeatures, Direct, SkipUnresponsivePeers
from typing import List, Tuple
from utils import testing
from utils.asyncio_util import run_async_context
from utils.connection_util import (
    ConnectionTag,
    generate_connection_tracker_config,
    ConnectionLimits,
)
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
    cfg: List[Tuple[ConnectionTag, List[str]]]
) -> List[SetupParameters]:
    return [
        SetupParameters(
            connection_tag=conn_tag,
            adapter_type=telio.AdapterType.BoringTun,
            features=TelioFeatures(
                direct=Direct(
                    providers=endpoint_providers,
                    skip_unresponsive_peers=SkipUnresponsivePeers(
                        no_handshake_threshold_secs=10
                    ),
                )
            ),
            connection_tracker_config=generate_connection_tracker_config(
                conn_tag,
                derp_0_limits=ConnectionLimits(0, 1),
                derp_1_limits=ConnectionLimits(1, 3),
                derp_2_limits=ConnectionLimits(0, 3),
                derp_3_limits=ConnectionLimits(0, 3),
                ping_limits=ConnectionLimits(0, 5),
            ),
        )
        for conn_tag, endpoint_providers in cfg
    ]


UHP_WORKING_PATHS = [
    pytest.param(
        _generate_setup_parameter_pair(
            [
                (ConnectionTag.DOCKER_FULLCONE_CLIENT_1, ["stun"]),
                (ConnectionTag.DOCKER_FULLCONE_CLIENT_2, ["stun"]),
            ]
        ),
        DOCKER_FULLCONE_GW_2_IP,
    ),
    pytest.param(
        _generate_setup_parameter_pair(
            [
                (ConnectionTag.DOCKER_SYMMETRIC_CLIENT_1, ["stun"]),
                (ConnectionTag.DOCKER_FULLCONE_CLIENT_1, ["stun"]),
            ]
        ),
        DOCKER_FULLCONE_GW_1_IP,
    ),
    pytest.param(
        _generate_setup_parameter_pair(
            [
                (ConnectionTag.DOCKER_OPEN_INTERNET_CLIENT_1, ["stun"]),
                (ConnectionTag.DOCKER_FULLCONE_CLIENT_1, ["stun"]),
            ]
        ),
        DOCKER_FULLCONE_GW_1_IP,
    ),
    pytest.param(
        _generate_setup_parameter_pair(
            [
                (ConnectionTag.DOCKER_CONE_CLIENT_1, ["stun"]),
                (ConnectionTag.DOCKER_FULLCONE_CLIENT_1, ["stun"]),
            ]
        ),
        DOCKER_FULLCONE_GW_1_IP,
    ),
    pytest.param(
        _generate_setup_parameter_pair(
            [
                (ConnectionTag.DOCKER_CONE_CLIENT_1, ["stun"]),
                (ConnectionTag.DOCKER_CONE_CLIENT_2, ["stun"]),
            ]
        ),
        DOCKER_CONE_GW_2_IP,
    ),
    pytest.param(
        _generate_setup_parameter_pair(
            [
                (ConnectionTag.DOCKER_CONE_CLIENT_1, ["stun"]),
                (ConnectionTag.DOCKER_OPEN_INTERNET_CLIENT_1, ["stun"]),
            ]
        ),
        DOCKER_OPEN_INTERNET_CLIENT_1_IP,
    ),
    pytest.param(
        _generate_setup_parameter_pair(
            [
                (ConnectionTag.DOCKER_OPEN_INTERNET_CLIENT_1, ["stun"]),
                (ConnectionTag.DOCKER_OPEN_INTERNET_CLIENT_2, ["stun"]),
            ]
        ),
        DOCKER_OPEN_INTERNET_CLIENT_2_IP,
    ),
    pytest.param(
        _generate_setup_parameter_pair(
            [
                (ConnectionTag.DOCKER_SYMMETRIC_CLIENT_1, ["stun"]),
                (ConnectionTag.DOCKER_OPEN_INTERNET_CLIENT_1, ["stun"]),
            ]
        ),
        DOCKER_OPEN_INTERNET_CLIENT_1_IP,
    ),
    pytest.param(
        _generate_setup_parameter_pair(
            [
                (ConnectionTag.DOCKER_UPNP_CLIENT_1, ["upnp"]),
                (ConnectionTag.DOCKER_UPNP_CLIENT_2, ["upnp"]),
            ]
        ),
        DOCKER_UPNP_CLIENT_2_IP,
    ),
    pytest.param(
        _generate_setup_parameter_pair(
            [
                (ConnectionTag.DOCKER_OPEN_INTERNET_CLIENT_DUAL_STACK, ["stun"]),
                (ConnectionTag.DOCKER_OPEN_INTERNET_CLIENT_2, ["stun"]),
            ]
        ),
        DOCKER_OPEN_INTERNET_CLIENT_2_IP,
    ),
    pytest.param(
        _generate_setup_parameter_pair(
            [
                (ConnectionTag.DOCKER_OPEN_INTERNET_CLIENT_1, ["stun"]),
                (ConnectionTag.DOCKER_OPEN_INTERNET_CLIENT_DUAL_STACK, ["stun"]),
            ]
        ),
        DOCKER_OPEN_INTERNET_CLIENT_DUAL_STACK_IP,
    ),
    pytest.param(
        _generate_setup_parameter_pair(
            [
                (ConnectionTag.DOCKER_SYMMETRIC_CLIENT_1, ["local"]),
                (ConnectionTag.DOCKER_OPEN_INTERNET_CLIENT_1, ["local"]),
            ]
        ),
        DOCKER_OPEN_INTERNET_CLIENT_1_IP,
    ),
    pytest.param(
        _generate_setup_parameter_pair(
            [
                (ConnectionTag.DOCKER_CONE_CLIENT_1, ["local"]),
                (ConnectionTag.DOCKER_OPEN_INTERNET_CLIENT_1, ["local"]),
            ]
        ),
        DOCKER_OPEN_INTERNET_CLIENT_1_IP,
    ),
    pytest.param(
        _generate_setup_parameter_pair(
            [
                (ConnectionTag.DOCKER_FULLCONE_CLIENT_1, ["local"]),
                (ConnectionTag.DOCKER_OPEN_INTERNET_CLIENT_1, ["local"]),
            ]
        ),
        DOCKER_OPEN_INTERNET_CLIENT_1_IP,
    ),
    pytest.param(
        _generate_setup_parameter_pair(
            [
                (ConnectionTag.DOCKER_INTERNAL_SYMMETRIC_CLIENT, ["local"]),
                (ConnectionTag.DOCKER_SYMMETRIC_CLIENT_1, ["local"]),
            ]
        ),
        DOCKER_SYMMETRIC_CLIENT_1_IP,
    ),
]

UHP_FAILING_PATHS = [
    pytest.param(
        _generate_setup_parameter_pair(
            [
                (ConnectionTag.DOCKER_CONE_CLIENT_1, ANY_PROVIDERS),
                (ConnectionTag.DOCKER_SYMMETRIC_CLIENT_1, ANY_PROVIDERS),
            ]
        )
    ),
    pytest.param(
        _generate_setup_parameter_pair(
            [
                (ConnectionTag.DOCKER_CONE_CLIENT_1, ANY_PROVIDERS),
                (ConnectionTag.DOCKER_UDP_BLOCK_CLIENT_1, ANY_PROVIDERS),
            ]
        )
    ),
    pytest.param(
        _generate_setup_parameter_pair(
            [
                (ConnectionTag.DOCKER_SYMMETRIC_CLIENT_1, ANY_PROVIDERS),
                (ConnectionTag.DOCKER_SYMMETRIC_CLIENT_2, ANY_PROVIDERS),
            ]
        )
    ),
    pytest.param(
        _generate_setup_parameter_pair(
            [
                (ConnectionTag.DOCKER_SYMMETRIC_CLIENT_1, ANY_PROVIDERS),
                (ConnectionTag.DOCKER_UDP_BLOCK_CLIENT_1, ANY_PROVIDERS),
            ]
        )
    ),
    pytest.param(
        _generate_setup_parameter_pair(
            [
                (ConnectionTag.DOCKER_OPEN_INTERNET_CLIENT_1, ANY_PROVIDERS),
                (ConnectionTag.DOCKER_UDP_BLOCK_CLIENT_1, ANY_PROVIDERS),
            ]
        )
    ),
    pytest.param(
        _generate_setup_parameter_pair(
            [
                (ConnectionTag.DOCKER_UDP_BLOCK_CLIENT_1, ANY_PROVIDERS),
                (ConnectionTag.DOCKER_UDP_BLOCK_CLIENT_2, ANY_PROVIDERS),
            ]
        )
    ),
    pytest.param(
        _generate_setup_parameter_pair(
            [
                (ConnectionTag.DOCKER_OPEN_INTERNET_CLIENT_1, ["local"]),
                (ConnectionTag.DOCKER_FULLCONE_CLIENT_1, ["local"]),
            ]
        )
    ),
    pytest.param(
        _generate_setup_parameter_pair(
            [
                (ConnectionTag.DOCKER_CONE_CLIENT_1, ["local"]),
                (ConnectionTag.DOCKER_OPEN_INTERNET_CLIENT_1, ["local"]),
            ]
        )
    ),
    pytest.param(
        _generate_setup_parameter_pair(
            [
                (ConnectionTag.DOCKER_SYMMETRIC_CLIENT_1, ["local"]),
                (ConnectionTag.DOCKER_OPEN_INTERNET_CLIENT_1, ["local"]),
            ]
        )
    ),
]


@pytest.mark.asyncio
@pytest.mark.long
@pytest.mark.timeout(120)
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
                await testing.wait_long(ping.wait_for_next_ping())


@pytest.mark.asyncio
@pytest.mark.xfail(reason="test flaky - JIRA issue: LLT-4132")
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
            await testing.wait_long(ping.wait_for_next_ping())


@pytest.mark.asyncio
@pytest.mark.xfail(reason="test flaky - JIRA issue: LLT-4132")
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
                    await testing.wait_long(ping.wait_for_next_ping())
                except asyncio.TimeoutError:
                    pass
                else:
                    # if no timeout exception happens, this means, that peers connected through relay
                    # faster than we expected, but if no relay event occurs, this means, that something
                    # else was wrong, so we assert
                    await asyncio.wait_for(task, 1)

        async with Ping(alpha_connection, beta.ip_addresses[0]).run() as ping:
            await testing.wait_lengthy(ping.wait_for_next_ping())


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
                    await testing.wait_long(ping.wait_for_next_ping())
                except asyncio.TimeoutError:
                    pass
                else:
                    # if no timeout exception happens, this means, that peers connected through relay
                    # faster than we expected, but if no relay event occurs, this means, that something
                    # else was wrong, so we assert
                    await asyncio.wait_for(task, 1)

            await testing.wait_lengthy(task)

            async with Ping(alpha_connection, beta.ip_addresses[0]).run() as ping:
                await testing.wait_lengthy(ping.wait_for_next_ping())


@pytest.mark.asyncio
@pytest.mark.xfail(reason="test is flaky - LLT-4441")
@pytest.mark.parametrize("setup_params, _reflexive_ip", UHP_WORKING_PATHS)
async def test_direct_working_paths_with_skip_unresponsive_peers(
    setup_params: List[SetupParameters], _reflexive_ip: str
) -> None:
    async with AsyncExitStack() as exit_stack:
        env = await setup_mesh_nodes(exit_stack, setup_params)
        api = env.api
        alpha, beta = env.nodes
        alpha_client, beta_client = env.clients
        alpha_connection, _ = [conn.connection for conn in env.connections]

        async with Ping(alpha_connection, beta.ip_addresses[0]).run() as ping:
            await testing.wait_long(ping.wait_for_next_ping())

        await alpha_client.stop_device()

        await beta_client.wait_for_log(
            f"Skipping sending CMM to peer {alpha.public_key} (Unresponsive)"
        )

        await alpha_client.simple_start()
        await alpha_client.set_meshmap(api.get_meshmap(alpha.id))

        await testing.wait_defined(
            asyncio.gather(
                alpha_client.wait_for_state_peer(
                    beta.public_key,
                    [State.Connected],
                    [PathType.Direct],
                ),
                beta_client.wait_for_state_peer(
                    alpha.public_key,
                    [State.Connected],
                    [PathType.Direct],
                ),
            ),
            60,
        )

        async with Ping(alpha_connection, beta.ip_addresses[0]).run() as ping:
            await testing.wait_long(ping.wait_for_next_ping())


@pytest.mark.timeout(90)
@pytest.mark.asyncio
@pytest.mark.xfail(reason="test is flaky - LLT-4115")
@pytest.mark.parametrize(
    "setup_params",
    [
        pytest.param(
            _generate_setup_parameter_pair(
                [
                    (ConnectionTag.DOCKER_CONE_CLIENT_1, ["stun"]),
                    (ConnectionTag.DOCKER_CONE_CLIENT_2, ["stun"]),
                ]
            )
        ),
        pytest.param(
            _generate_setup_parameter_pair(
                [
                    (ConnectionTag.DOCKER_UPNP_CLIENT_1, ["upnp"]),
                    (ConnectionTag.DOCKER_UPNP_CLIENT_2, ["upnp"]),
                ]
            )
        ),
        pytest.param(
            _generate_setup_parameter_pair(
                [
                    (ConnectionTag.DOCKER_UPNP_CLIENT_1, ["upnp"]),
                    (ConnectionTag.DOCKER_CONE_CLIENT_2, ["stun"]),
                ]
            )
        ),
        pytest.param(
            _generate_setup_parameter_pair(
                [
                    (ConnectionTag.DOCKER_UPNP_CLIENT_1, ["upnp"]),
                    (ConnectionTag.DOCKER_OPEN_INTERNET_CLIENT_1, ["local"]),
                ]
            )
        ),
        pytest.param(
            _generate_setup_parameter_pair(
                [
                    (ConnectionTag.DOCKER_CONE_CLIENT_1, ["stun"]),
                    (ConnectionTag.DOCKER_OPEN_INTERNET_CLIENT_1, ["local"]),
                ]
            )
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
                    await testing.wait_lengthy(ping.wait_for_next_ping())

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
                await testing.wait_lengthy(ping.wait_for_next_ping())

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
@pytest.mark.xfail(reason="Test is flaky - JIRA issue LLT-4555")
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
            alpha_connection.create_process(
                [
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
                ]
            ).run()
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
