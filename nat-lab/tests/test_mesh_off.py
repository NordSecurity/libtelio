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
    "direct",
    [True, False],
)
async def test_mesh_off(direct) -> None:
    async with AsyncExitStack() as exit_stack:
        features = (
            TelioFeatures(direct=Direct(providers=None))
            if direct
            else TelioFeatures(direct=None)
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

        path_type = PathType.Direct if direct else PathType.Relay

        await client_alpha.wait_for_state_peer(
            beta.public_key, [State.Disconnected], [path_type]
        )

        await client_alpha.set_meshmap(env.api.get_meshmap(alpha.id))

        asyncio.gather(
            client_alpha.wait_for_state_peer(
                beta.public_key, [State.Connected], [path_type]
            ),
            client_beta.wait_for_state_peer(
                alpha.public_key, [State.Connected], [path_type]
            ),
        )

        async with Ping(connection_alpha, beta.ip_addresses[0]).run() as ping:
            await ping.wait_for_next_ping()
        async with Ping(connection_beta, alpha.ip_addresses[0]).run() as ping:
            await ping.wait_for_next_ping()
