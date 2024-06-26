import asyncio
import pytest
import telio
from contextlib import AsyncExitStack
from helpers import SetupParameters, setup_mesh_nodes
from telio import PathType, State
from telio_features import TelioFeatures, Direct
from utils.connection_util import ConnectionTag
from utils.iperf3 import IperfServer, IperfClient, Protocol
from utils.ping import Ping


@pytest.mark.asyncio
@pytest.mark.mytests
@pytest.mark.parametrize(
    "disable_connected_socket_b",
    [True, False],
)
@pytest.mark.parametrize(
    "beta_tag",
    # [ConnectionTag.MAC_VM, ConnectionTag.DOCKER_OPEN_INTERNET_CLIENT_2],
    [ConnectionTag.DOCKER_OPEN_INTERNET_CLIENT_2],
)
async def test_mesh_connected_socket(disable_connected_socket_b, beta_tag) -> None:
    async with AsyncExitStack() as exit_stack:
        features_beta = TelioFeatures(
            direct=Direct(providers=["stun", "local"]),
            disable_connected_socket=disable_connected_socket_b,
        )
        env = await setup_mesh_nodes(
            exit_stack,
            [
                SetupParameters(
                    connection_tag=ConnectionTag.DOCKER_OPEN_INTERNET_CLIENT_1,
                    adapter_type=telio.AdapterType.BoringTun,
                    features=TelioFeatures(
                        direct=Direct(providers=["stun", "local"]),
                    ),
                ),
                SetupParameters(
                    connection_tag=beta_tag,
                    adapter_type=telio.AdapterType.BoringTun,
                    features=features_beta,
                ),
            ],
        )
        alpha, beta = env.nodes

        connection_alpha, connection_beta = [
            conn.connection for conn in env.connections
        ]

        async with Ping(connection_alpha, beta.ip_addresses[0]).run() as ping:
            await ping.wait_for_next_ping()
        async with Ping(connection_beta, alpha.ip_addresses[0]).run() as ping:
            await ping.wait_for_next_ping()

        async with IperfServer(connection_alpha, "server").run():
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
