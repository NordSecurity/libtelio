import asyncio
import pytest
from contextlib import AsyncExitStack
from tests import config
from tests.utils.connection import Connection, TargetOS, ConnectionTag
from tests.utils.connection_util import new_connection_by_tag
from tests.utils.process import ProcessExecError
from tests.utils.testing import log_test_passed


async def _get_running_process_list(connection: Connection) -> str:
    command = ["ps", "aux"]
    if connection.target_os is TargetOS.Windows:
        command = [
            "powershell",
            "-Command",
            "Get-WmiObject Win32_Process | Select-Object -ExpandProperty CommandLine",
        ]
    return (await connection.create_process(command).execute()).get_stdout()


@pytest.mark.parametrize(
    "connection_tag,command",
    [
        pytest.param(ConnectionTag.DOCKER_CONE_CLIENT_1, ["/usr/bin/ls"]),
        pytest.param(
            ConnectionTag.VM_WINDOWS_1, ["dir", "C:"], marks=pytest.mark.windows
        ),
        pytest.param(ConnectionTag.VM_MAC, ["/bin/ls"], marks=pytest.mark.mac),
    ],
)
async def test_process_execute_success(
    connection_tag: ConnectionTag, command: list[str]
):
    async with AsyncExitStack() as exit_stack:
        connection = await exit_stack.enter_async_context(
            new_connection_by_tag(connection_tag)
        )
        await connection.create_process(command).execute()
        assert " ".join(command) not in await _get_running_process_list(connection)
        log_test_passed()


@pytest.mark.parametrize(
    "connection_tag",
    [
        pytest.param(ConnectionTag.DOCKER_CONE_CLIENT_1),
        pytest.param(ConnectionTag.VM_WINDOWS_1, marks=pytest.mark.windows),
        pytest.param(ConnectionTag.VM_MAC, marks=pytest.mark.mac),
    ],
)
async def test_process_execute_fail(connection_tag: ConnectionTag):
    async with AsyncExitStack() as exit_stack:
        command = "non_existing_binary"
        connection = await exit_stack.enter_async_context(
            new_connection_by_tag(connection_tag)
        )
        with pytest.raises(ProcessExecError) as e:
            await connection.create_process([command]).execute()
        assert e.value.cmd == [command]
        assert command not in await _get_running_process_list(connection)
        log_test_passed()


@pytest.mark.parametrize(
    "connection_tag,ping_command",
    [
        pytest.param(
            ConnectionTag.DOCKER_CONE_CLIENT_1,
            ["ping", config.PHOTO_ALBUM_IP],
        ),
        pytest.param(
            ConnectionTag.VM_WINDOWS_1,
            ["ping", "-t", config.PHOTO_ALBUM_IP],
            marks=pytest.mark.windows,
        ),
        pytest.param(
            ConnectionTag.VM_MAC,
            ["ping", config.PHOTO_ALBUM_IP],
            marks=pytest.mark.mac,
        ),
    ],
)
async def test_process_run_success(
    connection_tag: ConnectionTag, ping_command: list[str]
):
    async with AsyncExitStack() as exit_stack:
        connection = await exit_stack.enter_async_context(
            new_connection_by_tag(connection_tag)
        )
        async with connection.create_process(ping_command).run() as process:
            await process.wait_stdin_ready()
            while (
                config.PHOTO_ALBUM_IP not in process.get_stdout()
                and config.PHOTO_ALBUM_IP not in process.get_stderr()
            ):
                await asyncio.sleep(0.1)
            assert " ".join(ping_command) in await _get_running_process_list(connection)
        assert " ".join(ping_command) not in await _get_running_process_list(connection)
        log_test_passed()


@pytest.mark.parametrize(
    "connection_tag,command",
    [
        pytest.param(
            ConnectionTag.DOCKER_CONE_CLIENT_1,
            ["bash", "-c", "exit 77"],
        ),
        pytest.param(
            ConnectionTag.VM_WINDOWS_1,
            ["cmd.exe", "/c", "exit 77"],
            marks=pytest.mark.windows,
        ),
        pytest.param(
            ConnectionTag.VM_MAC,
            ["bash", "-c", "exit 77"],
            marks=pytest.mark.mac,
        ),
    ],
)
async def test_process_run_fail(connection_tag: ConnectionTag, command: list[str]):
    async with AsyncExitStack() as exit_stack:
        connection = await exit_stack.enter_async_context(
            new_connection_by_tag(connection_tag)
        )
        with pytest.raises(ProcessExecError) as e:
            async with connection.create_process(command).run() as process:
                await process.is_done()
        assert e.value.cmd == command
        assert e.value.returncode == 77
        assert " ".join(command) not in await _get_running_process_list(connection)
        log_test_passed()


@pytest.mark.parametrize(
    "connection_tag",
    [
        pytest.param(
            ConnectionTag.DOCKER_CONE_CLIENT_1,
        ),
        pytest.param(
            ConnectionTag.VM_WINDOWS_1,
            marks=pytest.mark.windows,
        ),
        pytest.param(
            ConnectionTag.VM_MAC,
            marks=pytest.mark.mac,
        ),
    ],
)
async def test_process_run_not_found(connection_tag: ConnectionTag):
    async with AsyncExitStack() as exit_stack:
        connection = await exit_stack.enter_async_context(
            new_connection_by_tag(connection_tag)
        )
        command = "non_existing_binary"
        with pytest.raises(ProcessExecError) as e:
            async with connection.create_process([command]).run() as process:
                await process.is_done()
        assert e.value.cmd == [command]
        assert command not in await _get_running_process_list(connection)
        log_test_passed()


@pytest.mark.parametrize(
    "connection_tag,ping_command",
    [
        pytest.param(
            ConnectionTag.DOCKER_CONE_CLIENT_1,
            ["ping", config.PHOTO_ALBUM_IP],
        ),
        pytest.param(
            ConnectionTag.VM_WINDOWS_1,
            ["ping", "-t", config.PHOTO_ALBUM_IP],
            marks=pytest.mark.windows,
        ),
        pytest.param(
            ConnectionTag.VM_MAC,
            ["ping", config.PHOTO_ALBUM_IP],
            marks=pytest.mark.mac,
        ),
    ],
)
async def test_process_run_cancel(
    connection_tag: ConnectionTag, ping_command: list[str]
):
    async with AsyncExitStack() as exit_stack:
        connection = await exit_stack.enter_async_context(
            new_connection_by_tag(connection_tag)
        )
        with pytest.raises(asyncio.CancelledError):
            async with connection.create_process(ping_command).run() as process:
                await process.wait_stdin_ready()
                while (
                    config.PHOTO_ALBUM_IP not in process.get_stdout()
                    and config.PHOTO_ALBUM_IP not in process.get_stderr()
                ):
                    await asyncio.sleep(0.1)
                assert " ".join(ping_command) in await _get_running_process_list(
                    connection
                )
                raise asyncio.CancelledError
        assert " ".join(ping_command) not in await _get_running_process_list(connection)
        log_test_passed()


@pytest.mark.parametrize(
    "connection_tag,ping_command",
    [
        pytest.param(
            ConnectionTag.DOCKER_CONE_CLIENT_1,
            ["ping", config.PHOTO_ALBUM_IP],
        ),
        pytest.param(
            ConnectionTag.VM_WINDOWS_1,
            ["ping", "-t", config.PHOTO_ALBUM_IP],
            marks=pytest.mark.windows,
        ),
        pytest.param(
            ConnectionTag.VM_MAC,
            ["ping", config.PHOTO_ALBUM_IP],
            marks=pytest.mark.mac,
        ),
    ],
)
async def test_process_run_general_exception(
    connection_tag: ConnectionTag, ping_command: list[str]
):
    async with AsyncExitStack() as exit_stack:
        connection = await exit_stack.enter_async_context(
            new_connection_by_tag(connection_tag)
        )
        with pytest.raises(Exception):
            async with connection.create_process(ping_command).run() as process:
                await process.wait_stdin_ready()
                while (
                    config.PHOTO_ALBUM_IP not in process.get_stdout()
                    and config.PHOTO_ALBUM_IP not in process.get_stderr()
                ):
                    await asyncio.sleep(0.1)
                assert " ".join(ping_command) in await _get_running_process_list(
                    connection
                )
                raise Exception
        assert " ".join(ping_command) not in await _get_running_process_list(connection)
        log_test_passed()
