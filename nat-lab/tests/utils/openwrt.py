import asyncio
import asyncssh
from contextlib import AsyncExitStack
from tests.utils.connection import Connection
from tests.utils.logger import log
from tests.utils.process import Process, ProcessExecError


async def start_logread_process(
    connection: Connection,
    exit_stack: AsyncExitStack,
    log_line: str,
) -> Process:
    """
    Start a background logread process on the given connection
    and register it in the provided AsyncExitStack for automatic cleanup.

    Args:
        connection (Connection): Active SSH or Docker connection.
        exit_stack (AsyncExitStack): Context stack for managing async cleanup.
        log_line (str): Pattern to look for in logread output (grep filter).

    Returns:
        Process: The started SSH/Docker process streaming logs.
    """
    cmd = [
        "sh",
        "-c",
        f'logread -f | grep -i "{log_line}"',
    ]
    process = await exit_stack.enter_async_context(connection.create_process(cmd).run())
    return process


async def wait_until_unreachable_after_reboot(connection: Connection, delay: int = 1):
    """Wait until the existing connection becomes unreachable after rebooting."""
    while True:
        try:
            await connection.create_process(["true"]).execute()
        except (
            asyncssh.misc.ConnectionLost,
            asyncssh.misc.ChannelOpenError,
            asyncssh.misc.DisconnectError,
            OSError,
            asyncio.TimeoutError,
        ):
            log.debug("VM became unreachable — reboot likely in progress.")
            return
        await asyncio.sleep(delay)


async def read_uci_enabled(connection: Connection) -> str:
    proc = await connection.create_process(
        ["uci", "-q", "get", "nordvpnlite.settings.enabled"]
    ).execute()
    return proc.get_stdout().strip()


async def daemon_pid(connection: Connection) -> str:
    proc = await connection.create_process(
        ["sh", "-c", "pidof nordvpnlite || true"]
    ).execute()
    return proc.get_stdout().strip()


async def wait_for_new_daemon_pid(connection: Connection, old_pid: str) -> str:
    """Wait until a new nordvpnlite daemon process replaces old_pid, returning new pid.
    """
    while True:
        pid = await daemon_pid(connection)
        if pid and pid != old_pid:
            return pid
        await asyncio.sleep(1)


async def is_autostart_enabled(connection: Connection) -> bool:
    try:
        await connection.create_process(
            ["/etc/init.d/nordvpnlite", "enabled"]
        ).execute()
        return True
    except ProcessExecError:
        return False
