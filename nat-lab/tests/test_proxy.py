import asyncio
import pytest
from contextlib import AsyncExitStack
from tests.helpers import SetupParameters, setup_mesh_nodes
from tests.utils.bindings import TelioNode
from tests.utils.connection import ConnectionTag
from tests.utils.ping import ping
from tests.utils.testing import log_test_passed
from typing import Optional


@pytest.mark.asyncio
async def test_proxy_endpoint_map_update() -> None:
    setup_params = [
        SetupParameters(connection_tag=ConnectionTag.DOCKER_CONE_CLIENT_1),
        SetupParameters(connection_tag=ConnectionTag.DOCKER_CONE_CLIENT_2),
    ]

    async with AsyncExitStack() as exit_stack:
        env = await setup_mesh_nodes(exit_stack, setup_params)
        alpha, beta = env.nodes
        alpha_connection, beta_connection = [
            conn.connection for conn in env.connections
        ]
        alpha_client, _ = env.clients

        port = node_port(alpha_client.get_node_state(beta.public_key))

        await exit_stack.enter_async_context(
            alpha_client.get_router().block_udp_port(port)
        )

        await ping(alpha_connection, beta.ip_addresses[0])
        await ping(beta_connection, alpha.ip_addresses[0])

        for _ in range(0, 5):
            new_port = node_port(alpha_client.get_node_state(beta.public_key))
            if port != new_port:
                break
            await asyncio.sleep(1)
        else:
            assert False, "Endpoint wasn't successfully updated"

        # LLT-5532: To be cleaned up...
        alpha_client.allow_errors(
            ["telio_proxy::proxy.*Unable to send. Operation not permitted"]
        )
        log_test_passed()


def node_port(peer_info: Optional[TelioNode]) -> int:
    assert peer_info
    endpoint = peer_info.endpoint
    assert endpoint
    port = endpoint.split(":")[1]
    return int(port)
