import asyncio
import pytest
from contextlib import AsyncExitStack
from utils.connection_util import ConnectionTag, new_connection_by_tag
from utils.netcat import NetCat, NetCatServer, NetCatClient

TEST_STRING = "test data"
PORT = 12345

@pytest.mark.asyncio
@pytest.mark.timeout(30)
async def test_netcat() -> None:
    async with AsyncExitStack() as exit_stack:
        connection_1 = await exit_stack.enter_async_context(
            new_connection_by_tag(ConnectionTag.DOCKER_OPEN_INTERNET_CLIENT_1)
        )

        connection_2 = await exit_stack.enter_async_context(
            new_connection_by_tag(ConnectionTag.DOCKER_OPEN_INTERNET_CLIENT_2)
        )

        server_ip = await connection_1.get_ip_address()
        print(server_ip)

        async with NetCatServer(connection_1, PORT).run() as server:
            await server.listening_started()
            async with NetCatClient(connection_2, PORT, server_ip[1]).run() as client:
                # await client.connection_succeeded()
                # await server.connection_received()

                await asyncio.gather(
                    server.connection_received(),
                    client.connection_succeeded()
                )

                await client.send_data(TEST_STRING)

                server_data = await server.receive_data()
                print("DATA", server_data)
                assert server_data == TEST_STRING
