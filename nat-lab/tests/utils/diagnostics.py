from contextlib import AsyncExitStack
from tests.log_collector import clear_core_dumps
from tests.utils.connection import Connection
from tests.utils.tcpdump import make_tcpdump
from typing import List


async def setup_connection_diagnostics(
    exit_stack: AsyncExitStack,
    connections: List[Connection],
    *,
    run_tcpdump: bool = True,
) -> None:
    """Set up packet capture and core-dump collection for the given connections.

    This is test-environment setup, independent of any libtelio client: tcpdump
    records traffic on each connection for the duration of the test and any
    pre-existing core dumps are cleared up-front so that only dumps produced by
    the test are collected afterwards.
    """
    for connection in connections:
        # clear_core_dumps() decides internally whether the connection
        # is one we know how to collect dumps from (currently Docker
        # containers and Windows VMs) and is a no-op otherwise.
        await clear_core_dumps(connection)
    if run_tcpdump:
        await exit_stack.enter_async_context(make_tcpdump(connections))
