import asyncio
import pytest
from contextlib import AsyncExitStack
from helpers import SetupParameters, setup_mesh_nodes
from timeouts import TEST_MESH_STATE_AFTER_DISCONNECTING_NODE_TIMEOUT
from utils.bindings import (
    FeaturesDefaultsBuilder,
    FeatureLinkDetection,
    EndpointProvider,
    PathType,
    TelioAdapterType,
    NodeState,
)
from utils.connection_util import ConnectionTag
from utils.ping import ping


# Marks in-tunnel stack only, exiting only through IPv4
@pytest.mark.asyncio
@pytest.mark.parametrize(
    "direct",
    [True, False],
)
async def test_mesh_off(direct) -> None:
    async with AsyncExitStack() as exit_stack:
        if direct:
            telio_features = FeaturesDefaultsBuilder().enable_direct().build()
            assert telio_features.direct
            telio_features.direct.providers = None
        else:
            telio_features = FeaturesDefaultsBuilder().build()

        env = await setup_mesh_nodes(
            exit_stack,
            [
                SetupParameters(
                    connection_tag=ConnectionTag.DOCKER_CONE_CLIENT_1,
                    adapter_type=TelioAdapterType.LINUX_NATIVE_TUN,
                    features=telio_features,
                ),
                SetupParameters(
                    connection_tag=ConnectionTag.DOCKER_CONE_CLIENT_2,
                    adapter_type=TelioAdapterType.LINUX_NATIVE_TUN,
                    features=telio_features,
                ),
            ],
        )
        alpha, beta = env.nodes

        client_alpha, client_beta = env.clients
        connection_alpha, connection_beta = [
            conn.connection for conn in env.connections
        ]

        await client_alpha.set_mesh_off()

        # Checking if no peer is left after turning mesh net off
        # wg show outputs lines that start with the string "peer:" when any peer is present
        process = await connection_alpha.create_process([
            "wg",
            "show",
            "tun10",
        ]).execute()

        wg_show_stdout = process.get_stdout()

        assert (
            "peer:" not in wg_show_stdout.strip().split()
        ), f"There are leftover WireGuard peers after mesh is set to off: {wg_show_stdout}"

        path_type = PathType.DIRECT if direct else PathType.RELAY

        await client_alpha.wait_for_state_peer(
            beta.public_key, [NodeState.DISCONNECTED], [path_type]
        )

        await client_alpha.set_meshnet_config(env.api.get_meshnet_config(alpha.id))

        asyncio.gather(
            client_alpha.wait_for_state_peer(
                beta.public_key, [NodeState.CONNECTED], [path_type]
            ),
            client_beta.wait_for_state_peer(
                alpha.public_key, [NodeState.CONNECTED], [path_type]
            ),
        )

        await ping(connection_alpha, beta.ip_addresses[0])
        await ping(connection_beta, alpha.ip_addresses[0])


@pytest.mark.asyncio
@pytest.mark.timeout(TEST_MESH_STATE_AFTER_DISCONNECTING_NODE_TIMEOUT)
async def test_mesh_state_after_disconnecting_node() -> None:
    async with AsyncExitStack() as exit_stack:
        features = (
            FeaturesDefaultsBuilder().enable_direct().enable_link_detection().build()
        )
        assert features.direct
        features.direct.providers = [
            EndpointProvider.STUN,
            EndpointProvider.LOCAL,
            EndpointProvider.UPNP,
        ]
        features.link_detection = FeatureLinkDetection(
            rtt_seconds=5, no_of_pings=0, use_for_downgrade=False
        )
        env = await setup_mesh_nodes(
            exit_stack,
            [
                SetupParameters(
                    connection_tag=ConnectionTag.DOCKER_CONE_CLIENT_1,
                    features=features,
                ),
                SetupParameters(
                    connection_tag=ConnectionTag.DOCKER_CONE_CLIENT_2,
                    features=features,
                ),
            ],
        )
        alpha, beta = env.nodes
        client_alpha, client_beta = env.clients
        connection_alpha, connection_beta = [
            conn.connection for conn in env.connections
        ]

        await ping(connection_alpha, beta.ip_addresses[0])
        await ping(connection_beta, alpha.ip_addresses[0])

        await client_beta.stop_device()

        await client_alpha.wait_for_state_peer(
            beta.public_key, [NodeState.CONNECTING], list(PathType)
        )

        with pytest.raises(asyncio.TimeoutError):
            await client_alpha.wait_for_state_peer(
                beta.public_key, [NodeState.CONNECTED], list(PathType), timeout=15
            )

        await client_beta.simple_start()
        await client_beta.set_meshnet_config(env.api.get_meshnet_config(beta.id))

        await client_alpha.wait_for_state_peer(
            beta.public_key, [NodeState.CONNECTED], [PathType.DIRECT]
        )
