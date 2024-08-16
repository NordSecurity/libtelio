import asyncio
import pytest
from contextlib import AsyncExitStack
from helpers import setup_mesh_nodes, SetupParameters
from typing import List, Tuple
from utils.bindings import (
    FeaturesDefaultsBuilder,
    FeatureWireguard,
    FeatureLinkDetection,
    FeaturePersistentKeepalive,
    EndpointProvider,
    PathType,
    TelioAdapterType,
    NodeState,
)
from utils.connection_util import ConnectionTag
from utils.ping import ping


def long_persistent_keepalive_periods() -> FeatureWireguard:
    return FeatureWireguard(
        persistent_keepalive=FeaturePersistentKeepalive(
            proxying=3600, direct=3600, vpn=3600, stun=3600
        )
    )


def _generate_setup_parameter_pair(
    cfg: List[Tuple[ConnectionTag, TelioAdapterType]],
) -> List[SetupParameters]:
    features = FeaturesDefaultsBuilder().enable_link_detection().enable_direct().build()
    features.wireguard = long_persistent_keepalive_periods()
    features.link_detection = FeatureLinkDetection(
        rtt_seconds=1, no_of_pings=1, use_for_downgrade=True
    )
    assert features.direct
    features.direct.providers = [EndpointProvider.STUN, EndpointProvider.LOCAL]
    return [
        SetupParameters(
            connection_tag=tag,
            adapter_type=adapter,
            features=features,
        )
        for tag, adapter in cfg
    ]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "setup_params",
    [
        pytest.param(
            _generate_setup_parameter_pair([
                (ConnectionTag.DOCKER_CONE_CLIENT_1, TelioAdapterType.BORING_TUN),
                (ConnectionTag.DOCKER_CONE_CLIENT_2, TelioAdapterType.BORING_TUN),
            ])
        )
    ],
)
async def test_downgrade_using_link_detection(
    setup_params: List[SetupParameters],
) -> None:
    async with AsyncExitStack() as exit_stack:
        env = await setup_mesh_nodes(exit_stack, setup_params)
        alpha, beta = env.nodes
        alpha_client, beta_client = env.clients
        alpha_connection, beta_connection = [
            conn.connection for conn in env.connections
        ]

        # We have established a direct connection between the peers

        # Generate some traffic
        await ping(alpha_connection, beta.ip_addresses[0], 15)
        await ping(beta_connection, alpha.ip_addresses[0], 15)

        # Break the direct connection
        await exit_stack.enter_async_context(
            alpha_client.get_router().disable_path(
                alpha_client.get_endpoint_address(beta.public_key)
            )
        )
        await exit_stack.enter_async_context(
            beta_client.get_router().disable_path(
                beta_client.get_endpoint_address(alpha.public_key)
            )
        )

        # Generate some traffic to trigger link detection
        with pytest.raises(asyncio.TimeoutError):
            await ping(alpha_connection, beta.ip_addresses[0], 5)
        with pytest.raises(asyncio.TimeoutError):
            await ping(beta_connection, alpha.ip_addresses[0], 5)

        # Expect downgrade to relay
        await asyncio.gather(
            alpha_client.wait_for_state_peer(
                beta.public_key, [NodeState.CONNECTED], [PathType.RELAY], timeout=35
            ),
            beta_client.wait_for_state_peer(
                alpha.public_key, [NodeState.CONNECTED], [PathType.RELAY], timeout=35
            ),
        )

        # Check the relayed connection
        await ping(alpha_connection, beta.ip_addresses[0], 15)
        await ping(beta_connection, alpha.ip_addresses[0], 15)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "setup_params",
    [
        pytest.param(
            _generate_setup_parameter_pair([
                (ConnectionTag.DOCKER_CONE_CLIENT_1, TelioAdapterType.BORING_TUN),
                (ConnectionTag.DOCKER_CONE_CLIENT_2, TelioAdapterType.BORING_TUN),
            ])  # Disable enhanced detection via pinging to reduce the test duration
        )
    ],
)
async def test_downgrade_using_link_detection_with_silent_connection(
    setup_params: List[SetupParameters],
) -> None:
    async with AsyncExitStack() as exit_stack:
        env = await setup_mesh_nodes(exit_stack, setup_params)
        alpha, beta = env.nodes
        alpha_client, beta_client = env.clients
        alpha_connection, beta_connection = [
            conn.connection for conn in env.connections
        ]

        # We have established a direct connection between the peers

        # Generate some traffic
        await ping(alpha_connection, beta.ip_addresses[0], 15)
        await ping(beta_connection, alpha.ip_addresses[0], 15)

        # Wait for connection to stabilize
        # Leave time for the passive keepalives to be send
        await asyncio.sleep(15)

        # Break the direct connection
        await exit_stack.enter_async_context(
            alpha_client.get_router().disable_path(
                alpha_client.get_endpoint_address(beta.public_key)
            )
        )
        await exit_stack.enter_async_context(
            beta_client.get_router().disable_path(
                beta_client.get_endpoint_address(alpha.public_key)
            )
        )

        # Link detection should be in the state it sees this as a silent healthy connection
        # So expect no downgrade
        with pytest.raises(asyncio.TimeoutError):
            await asyncio.gather(
                alpha_client.wait_for_state_peer(
                    beta.public_key, [NodeState.CONNECTED], [PathType.RELAY], timeout=15
                ),
                beta_client.wait_for_state_peer(
                    alpha.public_key,
                    [NodeState.CONNECTED],
                    [PathType.RELAY],
                    timeout=15,
                ),
            )

        # Generate some traffic to trigger link detection
        with pytest.raises(asyncio.TimeoutError):
            await ping(alpha_connection, beta.ip_addresses[0], 5)
        with pytest.raises(asyncio.TimeoutError):
            await ping(beta_connection, alpha.ip_addresses[0], 5)

        # Expect downgrade to relay
        await asyncio.gather(
            alpha_client.wait_for_state_peer(
                beta.public_key, [NodeState.CONNECTED], [PathType.RELAY], timeout=35
            ),
            beta_client.wait_for_state_peer(
                alpha.public_key, [NodeState.CONNECTED], [PathType.RELAY], timeout=35
            ),
        )

        # Check the relayed connection
        await ping(alpha_connection, beta.ip_addresses[0], 15)
        await ping(beta_connection, alpha.ip_addresses[0], 15)
