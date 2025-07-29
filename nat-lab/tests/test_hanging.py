import pytest
from contextlib import AsyncExitStack
from utils.connection import ConnectionTag
from helpers import setup_connections


@pytest.mark.timeout(5)
async def test_hanging_timeout():
    async with AsyncExitStack() as exit_stack:
        connection = (
            await setup_connections(exit_stack, [ConnectionTag.DOCKER_CONE_CLIENT_1])
        )[0].connection

        output = (await connection.create_process(["ls"]).execute()).get_stdout()
        print(output)

        while True:
            pass  # simulate timeout
