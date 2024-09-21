import asyncio
from contextlib import AsyncExitStack
from helpers import setup_connections
from utils.connection_util import ConnectionTag

TELIOD_EXEC_PATH = "/libtelio/dist/linux/release/x86_64/teliod"
CONFIG_FILE_PATH = "/etc/teliod/config.json"

TELIOD_START_PARAMS = [
    TELIOD_EXEC_PATH,
    "daemon",
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
        teliod_process = await exit_stack.enter_async_context(
            connection.create_process(TELIOD_START_PARAMS).run()
        )

        # Let the daemon start
        await asyncio.sleep(1)

        # Try to run it again - some error message should be retuned
        assert (
            "Teliod is already running"
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

        assert teliod_process.is_executing()

        # Get Teliod PID
        teliod_pid = (
            await asyncio.wait_for(
                connection.create_process(["cat", "/run/teliod.pid"]).execute(),
                1,
            )
        ).get_stdout()

        print(f"Teliod PID: {teliod_pid}")

        # Send SIGTERM to the daemon
        await asyncio.wait_for(
            connection.create_process(["kill", f"{teliod_pid}"]).execute(),
            1,
        )

        # Let the daemon stop
        await asyncio.sleep(1)

        assert not teliod_process.is_executing()

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
