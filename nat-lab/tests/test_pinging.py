import asyncio
import pytest
import telio
from contextlib import AsyncExitStack
from helpers import setup_mesh_nodes, SetupParameters
from telio import PathType, State
from telio_features import TelioFeatures, Direct, Nurse, Qos, Lana
from typing import Tuple, List
from utils import testing
from utils.connection import Connection
from utils.connection_tracker import (
    ConnectionTracker,
    ConnectionTrackerConfig,
    ConnectionLimits,
)
from utils.connection_util import (
    generate_connection_tracker_config,
    new_connection_with_node_tracker,
    ConnectionTag,
)
from utils.router import IPStack

IP_STACKS = [
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
]


async def get_in_node_tracker(
    exit_stack: AsyncExitStack, tag: ConnectionTag, conf: List[ConnectionTrackerConfig]
) -> Tuple[Connection, ConnectionTracker]:
    return await exit_stack.enter_async_context(
        new_connection_with_node_tracker(tag, conf)
    )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "alpha_setup_params",
    [
        pytest.param(
            SetupParameters(
                adapter_type=telio.AdapterType.BoringTun,
                connection_tag=ConnectionTag.DOCKER_CONE_CLIENT_1,
                connection_tracker_config=generate_connection_tracker_config(
                    ConnectionTag.DOCKER_CONE_CLIENT_1,
                    derp_1_limits=ConnectionLimits(1, 1),
                ),
                features=TelioFeatures(
                    direct=Direct(providers=["stun"]),
                    ipv6=True,
                ),
            )
        ),
        pytest.param(
            SetupParameters(
                adapter_type=telio.AdapterType.LinuxNativeWg,
                connection_tag=ConnectionTag.DOCKER_CONE_CLIENT_1,
                connection_tracker_config=generate_connection_tracker_config(
                    ConnectionTag.DOCKER_CONE_CLIENT_1,
                    derp_1_limits=ConnectionLimits(1, 1),
                ),
                features=TelioFeatures(
                    direct=Direct(providers=["stun"]),
                    ipv6=True,
                ),
            ),
            marks=pytest.mark.linux_native,
        ),
    ],
)
@pytest.mark.parametrize(
    "alpha_ip_stack",
    IP_STACKS,
)
@pytest.mark.parametrize(
    "beta_setup_params",
    [
        pytest.param(
            SetupParameters(
                adapter_type=telio.AdapterType.BoringTun,
                connection_tag=ConnectionTag.DOCKER_CONE_CLIENT_2,
                connection_tracker_config=generate_connection_tracker_config(
                    ConnectionTag.DOCKER_CONE_CLIENT_2,
                    derp_1_limits=ConnectionLimits(1, 1),
                ),
                ip_stack=IPStack.IPv4v6,
                features=TelioFeatures(
                    direct=Direct(providers=["stun"]),
                    ipv6=True,
                ),
            )
        )
    ],
)
async def test_session_keeper(
    alpha_setup_params: SetupParameters,
    alpha_ip_stack: IPStack,
    beta_setup_params: SetupParameters,
) -> None:
    async with AsyncExitStack() as exit_stack:
        alpha_setup_params.ip_stack = alpha_ip_stack
        env = await setup_mesh_nodes(
            exit_stack, [alpha_setup_params, beta_setup_params]
        )

        alpha, beta = env.nodes
        alpha_client, beta_client = env.clients

        (_, alpha_conn_tracker) = await get_in_node_tracker(
            exit_stack,
            alpha_setup_params.connection_tag,
            (
                generate_connection_tracker_config(
                    alpha_setup_params.connection_tag,
                    ping_limits=ConnectionLimits(1, 2),
                )
                if alpha_ip_stack == IPStack.IPv4
                else generate_connection_tracker_config(
                    alpha_setup_params.connection_tag,
                    ping6_limits=ConnectionLimits(1, 2),
                )
            ),
        )
        (_, beta_conn_tracker) = await get_in_node_tracker(
            exit_stack,
            beta_setup_params.connection_tag,
            (
                generate_connection_tracker_config(
                    beta_setup_params.connection_tag,
                    ping_limits=ConnectionLimits(1, 2),
                )
                if alpha_ip_stack == IPStack.IPv4
                else generate_connection_tracker_config(
                    beta_setup_params.connection_tag,
                    ping6_limits=ConnectionLimits(1, 2),
                )
            ),
        )

        async def wait_for_conntracker() -> None:
            while True:
                if (
                    alpha_conn_tracker.get_out_of_limits() is None
                    and beta_conn_tracker.get_out_of_limits() is None
                ):
                    return
                await asyncio.sleep(0.1)

        await asyncio.gather(
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
            testing.wait_defined(wait_for_conntracker(), 60),
        )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "alpha_setup_params",
    [
        pytest.param(
            SetupParameters(
                adapter_type=telio.AdapterType.BoringTun,
                connection_tag=ConnectionTag.DOCKER_CONE_CLIENT_1,
                connection_tracker_config=generate_connection_tracker_config(
                    ConnectionTag.DOCKER_CONE_CLIENT_1,
                    derp_1_limits=ConnectionLimits(1, 1),
                ),
                features=TelioFeatures(
                    lana=Lana(prod=False, event_path="/event.db"),
                    nurse=Nurse(
                        fingerprint="alpha_fingerprint",
                        qos=Qos(
                            rtt_interval=5, rtt_tries=1, rtt_types=["Ping"], buckets=1
                        ),
                        heartbeat_interval=10,
                        initial_heartbeat_interval=1,
                    ),
                    ipv6=True,
                ),
            )
        ),
        pytest.param(
            SetupParameters(
                adapter_type=telio.AdapterType.LinuxNativeWg,
                connection_tag=ConnectionTag.DOCKER_CONE_CLIENT_1,
                connection_tracker_config=generate_connection_tracker_config(
                    ConnectionTag.DOCKER_CONE_CLIENT_1,
                    derp_1_limits=ConnectionLimits(1, 1),
                ),
                features=TelioFeatures(
                    lana=Lana(prod=False, event_path="/event.db"),
                    nurse=Nurse(
                        fingerprint="alpha_fingerprint",
                        qos=Qos(
                            rtt_interval=5, rtt_tries=1, rtt_types=["Ping"], buckets=1
                        ),
                        heartbeat_interval=10,
                        initial_heartbeat_interval=1,
                    ),
                    ipv6=True,
                ),
            )
        ),
    ],
)
@pytest.mark.parametrize(
    "alpha_ip_stack",
    IP_STACKS,
)
@pytest.mark.parametrize(
    "beta_setup_params",
    [
        pytest.param(
            SetupParameters(
                adapter_type=telio.AdapterType.BoringTun,
                connection_tag=ConnectionTag.DOCKER_CONE_CLIENT_2,
                connection_tracker_config=generate_connection_tracker_config(
                    ConnectionTag.DOCKER_CONE_CLIENT_2,
                    derp_1_limits=ConnectionLimits(1, 1),
                ),
                ip_stack=IPStack.IPv4v6,
                features=TelioFeatures(
                    ipv6=True,
                ),
            )
        )
    ],
)
async def test_qos(
    alpha_setup_params: SetupParameters,
    alpha_ip_stack: IPStack,
    beta_setup_params: SetupParameters,
) -> None:
    async with AsyncExitStack() as exit_stack:
        alpha_setup_params.ip_stack = alpha_ip_stack
        env = await setup_mesh_nodes(
            exit_stack, [alpha_setup_params, beta_setup_params]
        )

        alpha, beta = env.nodes
        alpha_client, beta_client = env.clients

        (_, alpha_node_tracker) = await get_in_node_tracker(
            exit_stack,
            alpha_setup_params.connection_tag,
            (
                generate_connection_tracker_config(
                    alpha_setup_params.connection_tag,
                    derp_1_limits=ConnectionLimits(0, 1),
                    ping_limits=ConnectionLimits(1, 1),
                )
                if alpha_ip_stack == IPStack.IPv4
                else generate_connection_tracker_config(
                    alpha_setup_params.connection_tag,
                    derp_1_limits=ConnectionLimits(0, 1),
                    ping_limits=ConnectionLimits(1, 1),
                    ping6_limits=ConnectionLimits(1, 1),
                )
            ),
        )

        async def wait_for_conntracker() -> None:
            while True:
                if alpha_node_tracker.get_out_of_limits() is None:
                    return
                await asyncio.sleep(1.0)

        await asyncio.gather(
            alpha_client.wait_for_state_peer(
                beta.public_key,
                [State.Connected],
            ),
            beta_client.wait_for_state_peer(
                alpha.public_key,
                [State.Connected],
            ),
            testing.wait_defined(wait_for_conntracker(), 60),
        )
