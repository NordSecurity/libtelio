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
    await clear_core_dumps(connection)
    await clear_system_log(connection)
    if run_tcpdump:
        async with make_tcpdump([connection]):
            yield
    else:
        yield
