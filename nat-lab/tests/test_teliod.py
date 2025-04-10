import asyncio
import pytest
from config import LIBTELIO_BINARY_PATH_DOCKER
from contextlib import AsyncExitStack
from helpers import setup_connections
from utils.connection import ConnectionTag
from utils.process.process import ProcessExecError

TELIOD_EXEC_PATH = f"{LIBTELIO_BINARY_PATH_DOCKER}/teliod"
CONFIG_FILE_PATH = "/etc/teliod/config.json"
SOCKET_FILE_PATH = "/run/teliod.sock"

TELIOD_START_PARAMS = [
    TELIOD_EXEC_PATH,
    "daemon",
    CONFIG_FILE_PATH,
]

TELIOD_STATUS_PARAMS = [TELIOD_EXEC_PATH, "get-status"]


async def is_teliod_running(connection):
    try:
        await connection.create_process(["test", "-e", SOCKET_FILE_PATH]).execute()
        return True
    except:
        return False


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
        while not await is_teliod_running(connection):
            await asyncio.sleep(0.1)

        with pytest.raises(ProcessExecError) as err:
            await connection.create_process(TELIOD_START_PARAMS).execute()
        assert err.value.stderr == "Error: DaemonIsRunning"

        # Run the get-status command
        assert (
            "telio_is_running"
            in (
                await connection.create_process(TELIOD_STATUS_PARAMS).execute()
            ).get_stdout()
        )

        assert teliod_process.is_executing()

        # Send SIGTERM to the daemon
        await connection.create_process(
            ["killall", "-w", "-s", "SIGTERM", "teliod"]
        ).execute()

        assert not teliod_process.is_executing()
        assert not await is_teliod_running(connection)

        # Run the get-status command again - this time it should fail
        with pytest.raises(ProcessExecError) as err:
            await connection.create_process(TELIOD_STATUS_PARAMS).execute()
        assert err.value.stderr == "Error: DaemonIsNotRunning"
