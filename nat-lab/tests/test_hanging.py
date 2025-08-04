import asyncio
import itertools
import pytest
from contextlib import AsyncExitStack
from helpers import setup_connections, setup_mesh_nodes, SetupParameters
from utils.asyncio_util import run_async_context
from utils.bindings import (
    Features,
    default_features,
    FeatureLana,
    FeatureBatching,
    FeatureSkipUnresponsivePeers,
    FeatureEndpointProvidersOptimization,
    EndpointProvider,
    PathType,
    TelioAdapterType,
    NodeState,
    RelayState,
)
from utils.connection import ConnectionTag


@pytest.mark.timeout(5)
async def test_hanging_timeout():
    async with AsyncExitStack() as exit_stack:
        connection = (
            await setup_connections(exit_stack, [ConnectionTag.DOCKER_CONE_CLIENT_1])
        )[0].connection

        env = await setup_mesh_nodes(exit_stack, [])

        await asyncio.gather(*[
            await exit_stack.enter_async_context(
                run_async_context(
                    client.wait_for_state_peer(
                        node.public_key, [NodeState.CONNECTED], [PathType.RELAY]
                    )
                )
            )
            for client, node in itertools.product(env.clients, env.nodes)
            if not client.is_node(node)
        ])

        output = (await connection.create_process(["ls"]).execute()).get_stdout()
        print(output)

        while True:
            pass  # simulate timeout
