import asyncio
import pytest
import telio
from contextlib import AsyncExitStack
from datetime import datetime
from helpers import connectivity_stack, setup_mesh_nodes, SetupParameters
from telio import PathType, State
from telio_features import TelioFeatures, Direct, Nurse, Qos, Lana
from typing import Tuple
from utils.connection import Connection
from utils.connection_tracker import ConnectionTracker, ConnectionLimits
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


async def build_conntracker(
    exit_stack: AsyncExitStack,
    tag: ConnectionTag,
    primary_ip_stack: IPStack,
    secondary_ip_stack: IPStack,
    for_session_keeper: bool = False,
) -> Tuple[Connection, ConnectionTracker]:
    # Set connection tracker expectations according to IP stack parameter
    connection = connectivity_stack(primary_ip_stack, secondary_ip_stack)

    ping_limits = ConnectionLimits(0, 0)
    ping6_limits = ConnectionLimits(0, 0)

    if connection == IPStack.IPv4:
        ping_limits = ConnectionLimits(1, 2)
    elif connection == IPStack.IPv6:
        ping6_limits = ConnectionLimits(1, 2)
    elif connection == IPStack.IPv4v6:
        # Session keeper prioritizes IPv6, and only when IPv6 is not available, it uses IPv4
        if not for_session_keeper:
            ping_limits = ConnectionLimits(1, 2)
        ping6_limits = ConnectionLimits(1, 2)

    conntrack_config = generate_connection_tracker_config(
        tag,
        derp_1_limits=ConnectionLimits(1, 1),
        ping_limits=ping_limits,
        ping6_limits=ping6_limits,
    )

    return await exit_stack.enter_async_context(
        new_connection_with_node_tracker(tag, conntrack_config)
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

        # Initialize node conntracker before starting nodes
        _, alpha_conntrack = await build_conntracker(
            exit_stack,
            alpha_setup_params.connection_tag,
            alpha_ip_stack,
            beta_setup_params.ip_stack,
            for_session_keeper=True,
        )
        _, beta_conntrack = await build_conntracker(
            exit_stack,
            beta_setup_params.connection_tag,
            alpha_ip_stack,
            beta_setup_params.ip_stack,
            for_session_keeper=True,
        )

        # Startup meshnet
        env = await setup_mesh_nodes(
            exit_stack, [alpha_setup_params, beta_setup_params]
        )

        alpha, beta = env.nodes
        alpha_client, beta_client = env.clients

        async def wait_for_conntracker() -> None:
            while True:
                alpha_limits = await alpha_conntrack.get_out_of_limits()
                beta_limits = await beta_conntrack.get_out_of_limits()
                print(datetime.now(), "Conntracker state: ", alpha_limits, beta_limits)
                if alpha_limits is None and beta_limits is None:
                    return
                await asyncio.sleep(1)

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
            wait_for_conntracker(),
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
                        qos=Qos(
                            rtt_interval=5, rtt_tries=1, rtt_types=["Ping"], buckets=1
                        ),
                        heartbeat_interval=10,
                        initial_heartbeat_interval=1,
                    ),
                    ipv6=True,
                ),
                fingerprint="alpha_fingerprint",
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
                        qos=Qos(
                            rtt_interval=5, rtt_tries=1, rtt_types=["Ping"], buckets=1
                        ),
                        heartbeat_interval=10,
                        initial_heartbeat_interval=1,
                    ),
                    ipv6=True,
                ),
                fingerprint="alpha_fingerprint",
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

        # Setup conntracking before mesh startup
        _, alpha_conntrack = await build_conntracker(
            exit_stack,
            alpha_setup_params.connection_tag,
            alpha_setup_params.ip_stack,
            beta_setup_params.ip_stack,
        )

        env = await setup_mesh_nodes(
            exit_stack, [alpha_setup_params, beta_setup_params]
        )

        alpha, beta = env.nodes
        alpha_client, beta_client = env.clients

        async def wait_for_conntracker() -> None:
            while True:
                alpha_limits = await alpha_conntrack.get_out_of_limits()
                print("wait_for_conntracker(): ", alpha_limits)
                if alpha_limits is None:
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
            wait_for_conntracker(),
        )
