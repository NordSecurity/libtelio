import asyncio
from contextlib import AsyncExitStack
from helpers import setup_connections
from utils.connection_util import ConnectionTag

TELIOD_EXEC_PATH = "/libtelio/dist/linux/release/x86_64/teliod"
CONFIG_FILE_PATH = "/etc/teliod/config.json"

TELIOD_START_PARAMS = [
    TELIOD_EXEC_PATH,
    "start",
    CONFIG_FILE_PATH,
]

TELIOD_HELLO_WORLD_PARAMS = [TELIOD_EXEC_PATH, "hello-world", "TestName"]

TELIOD_STOP_PARAMS = [TELIOD_EXEC_PATH, "stop"]


async def test_teliod() -> None:
    async with AsyncExitStack() as exit_stack:
        connection = (
            await setup_connections(exit_stack, [ConnectionTag.DOCKER_CONE_CLIENT_1])
        )[0].connection

        # Run teliod
        assert (
            "Starting Teliod daemon...Teliod daemon started"
            == (
                await asyncio.wait_for(
                    connection.create_process(TELIOD_START_PARAMS).execute(),
                    1,
                )
            ).get_stdout()
        )

        # Try to run it again - some error message should be retuned
        assert (
            "Teliod is already running, stop it by calling `teliod stop`"
            == (
                await asyncio.wait_for(
                    connection.create_process(TELIOD_START_PARAMS).execute(),
                    1,
                )
            ).get_stderr()
        )

        # Run the hello-world command
        assert (
            "Command executed successfully"
            == (
                await asyncio.wait_for(
                    connection.create_process(TELIOD_HELLO_WORLD_PARAMS).execute(),
                    1,
                )
            ).get_stdout()
        )

        # Stop teliod
        assert (
            "Command executed successfully"
            == (
                await asyncio.wait_for(
                    connection.create_process(TELIOD_STOP_PARAMS).execute(),
                    1,
                )
            ).get_stdout()
        )

        # Stopping while not runnign returns an error message
        assert (
            "Teliod daemon is not running"
            == (
                await asyncio.wait_for(
                    connection.create_process(TELIOD_STOP_PARAMS).execute(),
                    1,
                )
            ).get_stderr()
        )

        # Run the hello-world command again - this time it should fail
        assert (
            "Teliod daemon is not running"
            == (
                await asyncio.wait_for(
                    connection.create_process(TELIOD_HELLO_WORLD_PARAMS).execute(),
                    1,
                )
            ).get_stderr()
        )
