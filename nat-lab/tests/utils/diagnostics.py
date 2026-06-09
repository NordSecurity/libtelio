from contextlib import asynccontextmanager
from tests.log_collector import clear_core_dumps, clear_system_log
from tests.utils.connection import Connection
from tests.utils.tcpdump import make_tcpdump
from typing import AsyncIterator


@asynccontextmanager
async def connection_diagnostics(
    connection: Connection,
    *,
    run_tcpdump: bool = True,
) -> AsyncIterator[None]:
    """Set up packet capture and clear pre-test state for a single connection.

    This is connection-level test infrastructure, independent of any libtelio
    client: pre-existing core dumps and the (Windows) system log are cleared
    up-front so only artifacts from the test are collected, and tcpdump records
    traffic for the lifetime of the connection.
    """
    await clear_core_dumps(connection)
    await clear_system_log(connection)
    if run_tcpdump:
        async with make_tcpdump([connection]):
            yield
    else:
        yield
