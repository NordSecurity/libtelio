import asyncio
import pytest
from contextlib import AsyncExitStack
from utils.connection_util import ConnectionTag, new_connection_by_tag
from utils.netcat import NetCatServer, NetCatClient

TEST_STRING = "test data"
PORT = 12345


@pytest.mark.asyncio
@pytest.mark.timeout(10)
async def test_netcat() -> None:
    async with AsyncExitStack() as exit_stack:
        connection = await exit_stack.enter_async_context(
            new_connection_by_tag(ConnectionTag.DOCKER_CONE_CLIENT_1)
        )
        server_ip = (await connection.get_ip_address())[1]

        async with NetCatServer(connection, PORT).run() as server:
            await server.listening_started()
            async with NetCatClient(connection, server_ip, PORT).run() as client:
                await asyncio.gather(
                    server.connection_received(), client.connection_succeeded()
                )

                await client.send_data(TEST_STRING)
                server_data = await server.receive_data()
                assert server_data == TEST_STRING
