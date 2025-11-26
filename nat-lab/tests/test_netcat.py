import asyncio
import pytest
from contextlib import AsyncExitStack
from helpers import SetupParameters, setup_mesh_nodes
from utils.bindings import TelioAdapterType
from utils.connection import ConnectionTag
from utils.netcat import NetCatServer, NetCatClient

TEST_STRING = "test_data"
PORT = 12345


@pytest.mark.asyncio
@pytest.mark.timeout(30)
@pytest.mark.parametrize(
    "setup_params",
    [
        pytest.param(
            [
                SetupParameters(
                    connection_tag=ConnectionTag.VM_MAC,
                    adapter_type_override=TelioAdapterType.NEP_TUN,
                ),
                SetupParameters(
                    connection_tag=ConnectionTag.DOCKER_CONE_CLIENT_1,
                ),
            ],
            marks=pytest.mark.mac,
        ),
    ],
)
@pytest.mark.parametrize(
    "udp",
    [
        pytest.param(True),
        pytest.param(False),
    ],
)
async def test_netcat(setup_params: list[SetupParameters], udp: bool) -> None:
    async with AsyncExitStack() as exit_stack:
        env = await setup_mesh_nodes(exit_stack, setup_params)
        connection, client_connection, *_ = [
            conn.connection for conn in env.connections
        ]
        server_node, _ = env.nodes
        server_ip = server_node.ip_addresses[0]

        async with NetCatServer(
            connection, PORT, udp=udp, bind_ip=server_ip
        ).run() as server:
            await server.listening_started()
            async with NetCatClient(
                client_connection, server_ip, PORT, udp=udp
            ).run() as client:
                await asyncio.gather(
                    server.connection_received(), client.connection_succeeded()
                )

                await client.send_data(TEST_STRING)
                server_data = await server.receive_data()
                assert TEST_STRING in server_data
