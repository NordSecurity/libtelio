from contextlib import AsyncExitStack
from utils import ConnectionTag, new_connection_by_tag
import pytest


@pytest.mark.asyncio
async def test_docker_process_read_loop() -> None:
    async with AsyncExitStack() as exit_stack:
        connection = await exit_stack.enter_async_context(
            new_connection_by_tag(ConnectionTag.DOCKER_CONE_CLIENT_1)
        )
        TESTING_STRING = "☠"
        process = connection.create_process(
            [
                "bash",
                "-c",
                "for i in {0..1000000}; do printf '" + TESTING_STRING + "'; done",
            ]
        )
        await process.execute()
        assert process.get_stdout().count(TESTING_STRING) == 1000001


async def test_docker_process_read_loop_invalid_utf() -> None:
    async with AsyncExitStack() as exit_stack:
        connection = await exit_stack.enter_async_context(
            new_connection_by_tag(ConnectionTag.DOCKER_CONE_CLIENT_1)
        )
        VALID_UTF = "☠"
        process = connection.create_process(
            [
                "bash",
                "-c",
                "for i in {0..1000000}; do printf '" + "\\xF8" + VALID_UTF + "'; done",
            ]
        )
        await process.execute()
        assert process.get_stdout().count(VALID_UTF) == 1000001
        assert process.get_stdout().count("\\xF8") == 0
