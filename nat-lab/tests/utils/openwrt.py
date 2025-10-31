from contextlib import AsyncExitStack
from utils.connection import Connection
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
