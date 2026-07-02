import os
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
    # Per-test packet captures are only useful when logs are collected (CI sets
    # NATLAB_SAVE_LOGS). Skipping the per-connection tcpdump spawn locally removes
    # a process + pcap download from every test's connection setup.
    if run_tcpdump and os.environ.get("NATLAB_SAVE_LOGS"):
        async with make_tcpdump([connection]):
            yield
    else:
        yield
