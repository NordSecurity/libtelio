import asyncio
import pytest
import telio
from contextlib import AsyncExitStack
from helpers import SetupParameters, setup_mesh_nodes
from telio import PathType, State
from telio_features import TelioFeatures, Direct
from utils.connection_util import ConnectionTag
from utils.ping import Ping


# Marks in-tunnel stack only, exiting only through IPv4
@pytest.mark.asyncio
@pytest.mark.parametrize(
    "disable_connected_socket",
    [True, False],
)
async def test_mesh_connected_socket(disable_connected_socket) -> None:
    async with AsyncExitStack() as exit_stack:
        features = TelioFeatures(
            direct=Direct(providers=["stun", "local", "upnp"]),
            disable_connected_socket=disable_connected_socket,
        )
        env = await setup_mesh_nodes(
            exit_stack,
            [
                SetupParameters(
                    connection_tag=ConnectionTag.DOCKER_CONE_CLIENT_1,
                    adapter_type=telio.AdapterType.LinuxNativeWg,
                    features=features,
                ),
                SetupParameters(
                    connection_tag=ConnectionTag.DOCKER_CONE_CLIENT_2,
                    adapter_type=telio.AdapterType.LinuxNativeWg,
                    features=features,
                ),
            ],
        )
        alpha, beta = env.nodes

        client_alpha, client_beta = env.clients
        connection_alpha, connection_beta = [
            conn.connection for conn in env.connections
        ]

        await client_alpha.set_meshmap(env.api.get_meshmap(alpha.id))

        asyncio.gather(
            client_alpha.wait_for_state_peer(
                beta.public_key, [State.Connected], [PathType.Direct]
            ),
            client_beta.wait_for_state_peer(
                alpha.public_key, [State.Connected], [PathType.Direct]
            ),
        )

        async with Ping(connection_alpha, beta.ip_addresses[0]).run() as ping:
            await ping.wait_for_next_ping()
        async with Ping(connection_beta, alpha.ip_addresses[0]).run() as ping:
            await ping.wait_for_next_ping()
