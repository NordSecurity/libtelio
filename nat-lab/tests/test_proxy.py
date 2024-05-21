import asyncio
import pytest
from contextlib import AsyncExitStack
from helpers import SetupParameters, setup_mesh_nodes
from telio import PeerInfo
from typing import Optional
from utils.connection_util import ConnectionTag
from utils.ping import Ping


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

        async with Ping(alpha_connection, beta.ip_addresses[0]).run() as ping:
            await ping.wait_for_next_ping()
        async with Ping(beta_connection, alpha.ip_addresses[0]).run() as ping:
            await ping.wait_for_next_ping()

        for _ in range(0, 5):
            new_port = node_port(alpha_client.get_node_state(beta.public_key))
            if port != new_port:
                break
            await asyncio.sleep(1)
        else:
            assert False, "Endpoint wasn't successfully updated"


def node_port(peer_info: Optional[PeerInfo]) -> int:
    assert peer_info
    endpoint = peer_info.endpoint
    assert endpoint
    port = endpoint.split(":")[1]
    return int(port)
