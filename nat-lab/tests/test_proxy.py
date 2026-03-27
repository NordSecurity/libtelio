import asyncio
import pytest
from contextlib import AsyncExitStack
from tests.helpers import SetupParameters, Environment
from tests.utils.bindings import TelioNode
from tests.utils.connection import ConnectionTag
from tests.utils.ping import ping
from typing import Optional

pytest_plugins = ["tests.helpers_fixtures"]


@pytest.mark.parametrize(
    "alpha_setup_params, beta_setup_params",
    [
        pytest.param(
            SetupParameters(connection_tag=ConnectionTag.DOCKER_CONE_CLIENT_1),
            SetupParameters(connection_tag=ConnectionTag.DOCKER_CONE_CLIENT_2),
        ),
    ],
)
@pytest.mark.asyncio
async def test_proxy_endpoint_map_update(
    alpha_setup_params: SetupParameters,  # pylint: disable=unused-argument
    beta_setup_params: SetupParameters,  # pylint: disable=unused-argument
    exit_stack: AsyncExitStack,
    env_mesh: Environment,
) -> None:
    alpha_node, beta_node = env_mesh.nodes[0], env_mesh.nodes[1]
    alpha_client = env_mesh.clients[0]
    alpha_conn, beta_conn = (
        env_mesh.connections[0].connection,
        env_mesh.connections[1].connection,
    )

    alpha = alpha_node
    beta = beta_node
    alpha_connection = alpha_conn
    beta_connection = beta_conn

    port = node_port(alpha_client.get_node_state(beta.public_key))

    await exit_stack.enter_async_context(alpha_client.get_router().block_udp_port(port))

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


def node_port(peer_info: Optional[TelioNode]) -> int:
    assert peer_info
    endpoint = peer_info.endpoint
    assert endpoint
    port = endpoint.split(":")[1]
    return int(port)
