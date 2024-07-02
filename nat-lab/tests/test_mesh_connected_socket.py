import asyncio
import pytest
import telio
from contextlib import AsyncExitStack
from helpers import SetupParameters, setup_mesh_nodes
from telio import PathType, State
from telio_features import TelioFeatures, Direct
from utils.connection_util import ConnectionTag
from utils.ping import Ping
from utils.iperf3 import IperfServer, IperfClient, Protocol


# Marks in-tunnel stack only, exiting only through IPv4
@pytest.mark.asyncio
@pytest.mark.parametrize(
    "disable_connected_socket_a",
    [True, False],
)
@pytest.mark.parametrize(
    "disable_connected_socket_b",
    [True, False],
)
async def test_mesh_connected_socket(
    disable_connected_socket_a, disable_connected_socket_b
) -> None:
    async with AsyncExitStack() as exit_stack:
        features_alpha = TelioFeatures(
            direct=Direct(providers=["stun", "local"]),
            disable_connected_socket=disable_connected_socket_a,
        )
        features_beta = TelioFeatures(
            direct=Direct(providers=["stun", "local"]),
            disable_connected_socket=disable_connected_socket_b,
        )
        env = await setup_mesh_nodes(
            exit_stack,
            [
                SetupParameters(
                    connection_tag=ConnectionTag.DOCKER_CONE_CLIENT_1,
                    adapter_type=telio.AdapterType.BoringTun,
                    features=features_alpha,
                ),
                SetupParameters(
                    connection_tag=ConnectionTag.DOCKER_CONE_CLIENT_2,
                    adapter_type=telio.AdapterType.BoringTun,
                    features=features_beta,
                ),
            ],
        )
        alpha, beta = env.nodes

        client_alpha, client_beta = env.clients
        connection_alpha, connection_beta = [
            conn.connection for conn in env.connections
        ]

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

        async with IperfServer(connection_alpha, "server").run():
            # await asyncio.sleep(1)

            async with IperfClient(
                alpha.ip_addresses[0],
                connection_beta,
                "client",
                4,
                protocol=Protocol.Tcp,
            ).run() as client:
                await client.done()
                out = client.get_stdout()
                print(f"iperf3 send: {out}")

                speed = client.get_speed()
                assert speed > 0, "No data sent"
                print(f"iperf3 send speed: {speed}")

            async with IperfClient(
                alpha.ip_addresses[0],
                connection_beta,
                "client",
                4,
                protocol=Protocol.Tcp,
                send=False,
            ).run() as client:
                await client.done()
                out = client.get_stdout()
                print(f"iperf3 receive: {out}")

                speed = client.get_speed()
                assert speed > 0, "No data received"
                print(f"iperf3 receive speed: {speed}")
