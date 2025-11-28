import asyncio
import pytest
from contextlib import AsyncExitStack
from tests.helpers import setup_mesh_nodes, SetupParameters, connectivity_stack
from tests.utils.bindings import (
    Features,
    default_features,
    FeatureQoS,
    EndpointProvider,
    RttType,
    PathType,
    TelioAdapterType,
    NodeState,
)
from tests.utils.connection import Connection, ConnectionTag
from tests.utils.connection_tracker import ConnectionTracker
from tests.utils.connection_util import (
    generate_connection_tracker_config,
    new_connection_with_node_tracker,
)
from tests.utils.logger import log
from tests.utils.router import IPStack
from typing import Tuple

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

    ping_limits = (0, 0)
    ping6_limits = (0, 0)

    if connection == IPStack.IPv4:
        ping_limits = (1, 2)
    elif connection == IPStack.IPv6:
        ping6_limits = (1, 2)
    elif connection == IPStack.IPv4v6:
        # Session keeper prioritizes IPv6, and only when IPv6 is not available, it uses IPv4
        if not for_session_keeper:
            ping_limits = (1, 2)
        ping6_limits = (1, 2)

    conntrack_config = generate_connection_tracker_config(
        tag,
        derp_1_limits=(1, 1),
        ping_limits=ping_limits,
        ping6_limits=ping6_limits,
    )

    return await exit_stack.enter_async_context(
        new_connection_with_node_tracker(tag, conntrack_config)
    )


def stun_features() -> Features:
    features = default_features(enable_direct=True, enable_ipv6=True)
    assert features.direct
    features.direct.providers = [EndpointProvider.STUN]
    return features


def nurse_features() -> Features:
    features = default_features(
        enable_lana=("/event.db", False),
        enable_nurse=True,
        enable_ipv6=True,
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
                adapter_type_override=TelioAdapterType.NEP_TUN,
                connection_tag=ConnectionTag.DOCKER_CONE_CLIENT_1,
                connection_tracker_config=generate_connection_tracker_config(
                    ConnectionTag.DOCKER_CONE_CLIENT_1,
                    derp_1_limits=(1, 1),
                ),
                features=stun_features(),
            )
        ),
        pytest.param(
            SetupParameters(
                adapter_type_override=TelioAdapterType.LINUX_NATIVE_TUN,
                connection_tag=ConnectionTag.DOCKER_CONE_CLIENT_1,
                connection_tracker_config=generate_connection_tracker_config(
                    ConnectionTag.DOCKER_CONE_CLIENT_1,
                    derp_1_limits=(1, 1),
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
                adapter_type_override=TelioAdapterType.NEP_TUN,
                connection_tag=ConnectionTag.DOCKER_CONE_CLIENT_2,
                connection_tracker_config=generate_connection_tracker_config(
                    ConnectionTag.DOCKER_CONE_CLIENT_2,
                    derp_1_limits=(1, 1),
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
                alpha_limits = await alpha_conntrack.find_conntracker_violations()
                beta_limits = await beta_conntrack.find_conntracker_violations()
                log.info("Conntracker state: %s %s", alpha_limits, beta_limits)
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
                adapter_type_override=TelioAdapterType.NEP_TUN,
                connection_tag=ConnectionTag.DOCKER_CONE_CLIENT_1,
                connection_tracker_config=generate_connection_tracker_config(
                    ConnectionTag.DOCKER_CONE_CLIENT_1,
                    derp_1_limits=(1, 1),
                ),
                features=nurse_features(),
                fingerprint="alpha_fingerprint",
            )
        ),
        pytest.param(
            SetupParameters(
                adapter_type_override=TelioAdapterType.LINUX_NATIVE_TUN,
                connection_tag=ConnectionTag.DOCKER_CONE_CLIENT_1,
                connection_tracker_config=generate_connection_tracker_config(
                    ConnectionTag.DOCKER_CONE_CLIENT_1,
                    derp_1_limits=(1, 1),
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
                adapter_type_override=TelioAdapterType.NEP_TUN,
                connection_tag=ConnectionTag.DOCKER_CONE_CLIENT_2,
                connection_tracker_config=generate_connection_tracker_config(
                    ConnectionTag.DOCKER_CONE_CLIENT_2,
                    derp_1_limits=(1, 1),
                ),
                ip_stack=IPStack.IPv4v6,
                features=default_features(enable_ipv6=True),
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
                alpha_limits = await alpha_conntrack.find_conntracker_violations()
                log.info("wait_for_conntracker(): %s", alpha_limits)
                if alpha_limits is None:
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
