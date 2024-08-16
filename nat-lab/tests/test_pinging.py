import asyncio
import pytest
from contextlib import AsyncExitStack
from datetime import datetime
from helpers import setup_mesh_nodes, SetupParameters
from typing import Tuple
from utils.bindings import (
    Features,
    FeaturesDefaultsBuilder,
    FeatureQoS,
    EndpointProvider,
    RttType,
    PathType,
    TelioAdapterType,
    NodeState,
)
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
    ip_stack: IPStack,
    qos_expected: bool,
) -> Tuple[Connection, ConnectionTracker]:
    # Set connection tracker expectations according to IP stack parameter
    conntrack_config = (
        generate_connection_tracker_config(
            tag,
            derp_1_limits=ConnectionLimits(1, 1),
            ping_limits=ConnectionLimits(1, 2),
        )
        if ip_stack == IPStack.IPv4
        else generate_connection_tracker_config(
            tag,
            derp_1_limits=ConnectionLimits(1, 1),
            ping_limits=(
                ConnectionLimits(1, 2) if qos_expected else ConnectionLimits(0, 0)
            ),
            ping6_limits=ConnectionLimits(1, 2),
        )
    )

    return await exit_stack.enter_async_context(
        new_connection_with_node_tracker(tag, conntrack_config)
    )


def stun_features() -> Features:
    features = FeaturesDefaultsBuilder().enable_direct().enable_ipv6().build()
    assert features.direct
    features.direct.providers = [EndpointProvider.STUN]
    return features


def nurse_features() -> Features:
    features = (
        FeaturesDefaultsBuilder()
        .enable_lana("/event.db", False)
        .enable_nurse()
        .enable_ipv6()
        .build()
    )
    assert features.nurse
    features.nurse.qos = FeatureQoS(
        rtt_interval=5, rtt_tries=1, rtt_types=[RttType.PING], buckets=1
    )
    features.nurse.heartbeat_interval = 10
    features.nurse.initial_heartbeat_interval = 1
    return features


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "alpha_setup_params",
    [
        pytest.param(
            SetupParameters(
                adapter_type=TelioAdapterType.BORING_TUN,
                connection_tag=ConnectionTag.DOCKER_CONE_CLIENT_1,
                connection_tracker_config=generate_connection_tracker_config(
                    ConnectionTag.DOCKER_CONE_CLIENT_1,
                    derp_1_limits=ConnectionLimits(1, 1),
                ),
                features=stun_features(),
            )
        ),
        pytest.param(
            SetupParameters(
                adapter_type=TelioAdapterType.LINUX_NATIVE_TUN,
                connection_tag=ConnectionTag.DOCKER_CONE_CLIENT_1,
                connection_tracker_config=generate_connection_tracker_config(
                    ConnectionTag.DOCKER_CONE_CLIENT_1,
                    derp_1_limits=ConnectionLimits(1, 1),
                ),
                features=stun_features(),
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
                adapter_type=TelioAdapterType.BORING_TUN,
                connection_tag=ConnectionTag.DOCKER_CONE_CLIENT_2,
                connection_tracker_config=generate_connection_tracker_config(
                    ConnectionTag.DOCKER_CONE_CLIENT_2,
                    derp_1_limits=ConnectionLimits(1, 1),
                ),
                ip_stack=IPStack.IPv4v6,
                features=stun_features(),
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
            exit_stack, alpha_setup_params.connection_tag, alpha_ip_stack, False
        )
        _, beta_conntrack = await build_conntracker(
            exit_stack, beta_setup_params.connection_tag, alpha_ip_stack, False
        )

        # Startup meshnet
        env = await setup_mesh_nodes(
            exit_stack, [alpha_setup_params, beta_setup_params]
        )

        alpha, beta = env.nodes
        alpha_client, beta_client = env.clients

        async def wait_for_conntracker() -> None:
            while True:
                alpha_limits = alpha_conntrack.get_out_of_limits()
                beta_limits = beta_conntrack.get_out_of_limits()
                print(datetime.now(), "Conntracker state: ", alpha_limits, beta_limits)
                if alpha_limits is None and beta_limits is None:
                    return
                await asyncio.sleep(1)

        await asyncio.gather(
            alpha_client.wait_for_state_peer(
                beta.public_key,
                [NodeState.CONNECTED],
                [PathType.DIRECT],
            ),
            beta_client.wait_for_state_peer(
                alpha.public_key,
                [NodeState.CONNECTED],
                [PathType.DIRECT],
            ),
            wait_for_conntracker(),
        )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "alpha_setup_params",
    [
        pytest.param(
            SetupParameters(
                adapter_type=TelioAdapterType.BORING_TUN,
                connection_tag=ConnectionTag.DOCKER_CONE_CLIENT_1,
                connection_tracker_config=generate_connection_tracker_config(
                    ConnectionTag.DOCKER_CONE_CLIENT_1,
                    derp_1_limits=ConnectionLimits(1, 1),
                ),
                features=nurse_features(),
                fingerprint="alpha_fingerprint",
            )
        ),
        pytest.param(
            SetupParameters(
                adapter_type=TelioAdapterType.LINUX_NATIVE_TUN,
                connection_tag=ConnectionTag.DOCKER_CONE_CLIENT_1,
                connection_tracker_config=generate_connection_tracker_config(
                    ConnectionTag.DOCKER_CONE_CLIENT_1,
                    derp_1_limits=ConnectionLimits(1, 1),
                ),
                features=nurse_features(),
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
                adapter_type=TelioAdapterType.BORING_TUN,
                connection_tag=ConnectionTag.DOCKER_CONE_CLIENT_2,
                connection_tracker_config=generate_connection_tracker_config(
                    ConnectionTag.DOCKER_CONE_CLIENT_2,
                    derp_1_limits=ConnectionLimits(1, 1),
                ),
                ip_stack=IPStack.IPv4v6,
                features=FeaturesDefaultsBuilder().enable_ipv6().build(),
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
            True,
        )

        env = await setup_mesh_nodes(
            exit_stack, [alpha_setup_params, beta_setup_params]
        )

        alpha, beta = env.nodes
        alpha_client, beta_client = env.clients

        async def wait_for_conntracker() -> None:
            while True:
                if alpha_conntrack.get_out_of_limits() is None:
                    return
                await asyncio.sleep(1.0)

        await asyncio.gather(
            alpha_client.wait_for_state_peer(
                beta.public_key,
                [NodeState.CONNECTED],
            ),
            beta_client.wait_for_state_peer(
                alpha.public_key,
                [NodeState.CONNECTED],
            ),
            wait_for_conntracker(),
        )
