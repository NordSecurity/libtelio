import asyncio
import pytest
import time
from config import LIBTELIO_BINARY_PATH_DOCKER
from contextlib import AsyncExitStack
from helpers import setup_connections
from utils.connection import ConnectionTag
from utils.process.process import ProcessExecError

TELIOD_EXEC_PATH = f"{LIBTELIO_BINARY_PATH_DOCKER}/teliod"
CONFIG_FILE_PATH = "/etc/teliod/config.json"
SOCKET_FILE_PATH = "/run/teliod.sock"
STDOUT_FILE_PATH = "/var/log/teliod.log"
LOG_FILE_PATH = "/var/log/teliod_natlab.log"

TELIOD_START_PARAMS = [
    TELIOD_EXEC_PATH,
    "start",
    CONFIG_FILE_PATH,
]

TELIOD_START_NODETACH_PARAMS = [
    TELIOD_EXEC_PATH,
    "start",
    "--no-detach",
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


WAIT_FOR_TELIOD_TIMEOUT = 3.0


async def wait_for_teliod(connection):
    start_time = time.monotonic()
    while time.monotonic() - start_time < WAIT_FOR_TELIOD_TIMEOUT:
        try:
            if await asyncio.wait_for(is_teliod_running(connection), 0.5):
                return
        except TimeoutError:
            pass
        await asyncio.sleep(0.1)
    raise TimeoutError("teliod did not start within timeout")


@pytest.mark.parametrize(
    "start_daemon_params",
    [(TELIOD_START_PARAMS), (TELIOD_START_NODETACH_PARAMS)],
    ids=["daemonized_mode", "no_detach_mode"],
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
        await wait_for_teliod(connection)

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
    [(TELIOD_START_PARAMS), (TELIOD_START_NODETACH_PARAMS)],
    ids=["daemonized_mode", "no_detach_mode"],
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
        await wait_for_teliod(connection)

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
            ["rm", "-f", STDOUT_FILE_PATH, LOG_FILE_PATH]
        ).execute()

        # Make sure they are indeed deleted
        for path in [STDOUT_FILE_PATH, LOG_FILE_PATH]:
            await connection.create_process(["test", "!", "-f", path]).execute()

        # Run teliod
        await exit_stack.enter_async_context(
            connection.create_process(TELIOD_START_PARAMS).run()
        )

        # Let the daemon start
        await wait_for_teliod(connection)

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

        # expected substrings for each log file
        expected_log_contents = {
            STDOUT_FILE_PATH: "task started",
            LOG_FILE_PATH: "telio::device",
        }

        # Check if log files exist and are not empty
        for path, expected_string in expected_log_contents.items():
            await connection.create_process(["test", "-s", path]).execute()
            await connection.create_process(
                ["grep", "-q", expected_string, path]
            ).execute()
