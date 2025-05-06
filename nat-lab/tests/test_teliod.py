import asyncio
import pytest
from config import LIBTELIO_BINARY_PATH_DOCKER
from contextlib import AsyncExitStack
from datetime import datetime
from helpers import setup_connections
from utils.connection import ConnectionTag
from utils.process.process import ProcessExecError

TELIOD_EXEC_PATH = f"{LIBTELIO_BINARY_PATH_DOCKER}/teliod"
CONFIG_FILE_PATH = "/etc/teliod/config.json"
SOCKET_FILE_PATH = "/run/teliod.sock"
STDOUT_FILE_PATH = "/var/log/teliod_stdout.log"
STDERR_FILE_PATH = "/var/log/teliod_stdout.log"
# Build today's dated log filename
LOG_FILE_PATH = f"/var/log/teliod_natlab.log.{datetime.today().strftime('%Y-%m-%d')}"

TELIOD_START_PARAMS = [
    TELIOD_EXEC_PATH,
    "daemon",
    CONFIG_FILE_PATH,
]

TELIOD_START_DAEMONIZE_PARAMS = [
    TELIOD_EXEC_PATH,
    "daemon",
    "-d",
    CONFIG_FILE_PATH,
]

TELIOD_STATUS_PARAMS = [TELIOD_EXEC_PATH, "get-status"]
TELIOD_IS_ALIVE_PARAMS = [TELIOD_EXEC_PATH, "is-alive"]
TELIOD_QUIT_DAEMON_PARAMS = [TELIOD_EXEC_PATH, "quit-daemon"]


async def is_teliod_running(connection):
    try:
        await connection.create_process(["test", "-e", SOCKET_FILE_PATH]).execute()
        return True
    except:
        return False


@pytest.mark.parametrize(
    "start_daemon_params",
    [(TELIOD_START_PARAMS), (TELIOD_START_DAEMONIZE_PARAMS)],
    ids=["process_mode", "daemonized_mode"],
)
async def test_teliod(start_daemon_params) -> None:
    async with AsyncExitStack() as exit_stack:
        connection = (
            await setup_connections(exit_stack, [ConnectionTag.DOCKER_CONE_CLIENT_1])
        )[0].connection

        # Run teliod
        await exit_stack.enter_async_context(
            connection.create_process(start_daemon_params).run()
        )

        # Let the daemon start
        while not await is_teliod_running(connection):
            await asyncio.sleep(0.1)

        with pytest.raises(ProcessExecError) as err:
            await connection.create_process(start_daemon_params).execute()
        assert err.value.stderr == "Error: DaemonIsRunning"

        # Run the get-status command
        assert (
            "telio_is_running"
            in (
                await connection.create_process(TELIOD_STATUS_PARAMS).execute()
            ).get_stdout()
        )

        # Send SIGTERM to the daemon
        await connection.create_process(
            ["killall", "-w", "-s", "SIGTERM", "teliod"]
        ).execute()

        assert not await is_teliod_running(connection)

        # Run the get-status command again - this time it should fail
        with pytest.raises(ProcessExecError) as err:
            await connection.create_process(TELIOD_STATUS_PARAMS).execute()
        assert err.value.stderr == "Error: DaemonIsNotRunning"


@pytest.mark.parametrize(
    "start_daemon_params",
    [(TELIOD_START_PARAMS), (TELIOD_START_DAEMONIZE_PARAMS)],
    ids=["process_mode", "daemonized_mode"],
)
async def test_teliod_quit(start_daemon_params) -> None:
    async with AsyncExitStack() as exit_stack:
        connection = (
            await setup_connections(exit_stack, [ConnectionTag.DOCKER_CONE_CLIENT_1])
        )[0].connection

        # Try to quit deamon that is not running
        with pytest.raises(ProcessExecError) as err:
            await connection.create_process(TELIOD_QUIT_DAEMON_PARAMS).execute()
        assert err.value.stderr == "Error: DaemonIsNotRunning"

        # Run teliod
        await exit_stack.enter_async_context(
            connection.create_process(start_daemon_params).run()
        )

        # Let the daemon start
        while not await is_teliod_running(connection):
            await asyncio.sleep(0.1)

        # Run the is-alive command
        assert (
            "Command executed successfully"
            in (
                await connection.create_process(TELIOD_IS_ALIVE_PARAMS).execute()
            ).get_stdout()
        )

        # Send quit-daemon command
        assert (
            "Command executed successfully"
            in (
                await connection.create_process(TELIOD_QUIT_DAEMON_PARAMS).execute()
            ).get_stdout()
        )

        assert not await is_teliod_running(connection)

        # Run the is-alive command again - this time it should fail
        with pytest.raises(ProcessExecError) as err:
            await connection.create_process(TELIOD_IS_ALIVE_PARAMS).execute()
        assert err.value.stderr == "Error: DaemonIsNotRunning"


async def test_teliod_logs() -> None:
    async with AsyncExitStack() as exit_stack:
        connection = (
            await setup_connections(exit_stack, [ConnectionTag.DOCKER_CONE_CLIENT_1])
        )[0].connection

        # Delete any old logs
        await connection.create_process(
            ["rm", "-f", STDOUT_FILE_PATH, STDERR_FILE_PATH, LOG_FILE_PATH]
        ).execute()

        # Make sure they are indeed deleted
        for path in [STDOUT_FILE_PATH, STDERR_FILE_PATH, LOG_FILE_PATH]:
            await connection.create_process(["test", "!", "-f", path]).execute()

        # Run teliod
        await exit_stack.enter_async_context(
            connection.create_process(TELIOD_START_DAEMONIZE_PARAMS).run()
        )

        # Let the daemon start
        while not await is_teliod_running(connection):
            await asyncio.sleep(0.1)

        # Run the is-alive command
        assert (
            "Command executed successfully"
            in (
                await connection.create_process(TELIOD_IS_ALIVE_PARAMS).execute()
            ).get_stdout()
        )

        # Send quit-daemon command
        assert (
            "Command executed successfully"
            in (
                await connection.create_process(TELIOD_QUIT_DAEMON_PARAMS).execute()
            ).get_stdout()
        )

        assert not await is_teliod_running(connection)

        # Check if log files exist
        for path in [STDOUT_FILE_PATH, STDERR_FILE_PATH, LOG_FILE_PATH]:
            await connection.create_process(["test", "-f", path]).execute()
