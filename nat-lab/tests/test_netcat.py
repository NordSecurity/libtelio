import asyncio
import pytest
from contextlib import AsyncExitStack
from helpers import SetupParameters, setup_environment
from utils.connection_util import ConnectionTag
from utils.netcat import NetCatServer, NetCatClient

TEST_STRING = "test_data"
PORT = 12345


@pytest.mark.asyncio
@pytest.mark.timeout(30)
@pytest.mark.parametrize(
    "setup_params",
    [
        pytest.param(
            SetupParameters(
                connection_tag=ConnectionTag.DOCKER_CONE_CLIENT_1,
            )
        ),
        pytest.param(
            SetupParameters(
                connection_tag=ConnectionTag.MAC_VM,
            ),
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
async def test_netcat(setup_params: SetupParameters, udp: bool) -> None:
    async with AsyncExitStack() as exit_stack:
        env = await exit_stack.enter_async_context(
            setup_environment(exit_stack, [setup_params])
        )
        connection, *_ = [conn.connection for conn in env.connections]
        server_ip = (await connection.get_ip_address())[1]

        async with NetCatServer(connection, PORT, udp=udp).run() as server:
            await server.listening_started()
            async with NetCatClient(
                connection, server_ip, PORT, udp=udp
            ).run() as client:
                await asyncio.gather(
                    server.connection_received(), client.connection_succeeded()
                )

                await client.send_data(TEST_STRING)
                server_data = await server.receive_data()
                assert TEST_STRING in server_data
