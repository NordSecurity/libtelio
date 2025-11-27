import asyncio
import asyncssh
from contextlib import AsyncExitStack
from utils.connection import Connection
from utils.logger import log
from utils.process import Process


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


async def wait_until_unreachable_after_reboot(
    connection: Connection, retries: int = 5, delay: int = 1
):
    """Wait until the existing connection becomes unreachable after rebooting."""
    for _ in range(1, retries + 1):
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

    raise TimeoutError(
        f"VM still reachable after {retries} retries — reboot may not have started."
    )
