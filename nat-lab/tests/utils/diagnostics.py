from contextlib import AsyncExitStack
from tests.log_collector import clear_core_dumps
from tests.utils.bindings import TelioAdapterType
from tests.utils.connection import Connection
from tests.utils.perf_profiling import PerfProfiler
from tests.utils.tcpdump import make_tcpdump
from typing import Optional


async def setup_run_diagnostics(
    exit_stack: AsyncExitStack,
    connection: Connection,
    adapter_type: TelioAdapterType,
    *,
    run_tcpdump: Optional[bool],
    enable_perf: Optional[bool],
) -> None:
    """Enter the per-run diagnostics context managers (perf, tcpdump, coredumps).

    Extracted from `Client.run()` so the client no longer owns this orchestration.
    """
    if enable_perf:
        await exit_stack.enter_async_context(
            PerfProfiler(
                connection=connection,
                file_name_suffix=adapter_type.name.lower(),
            )
        )
    if run_tcpdump:
        await exit_stack.enter_async_context(make_tcpdump([connection]))
    # clear_core_dumps() decides internally whether the connection
    # is one we know how to collect dumps from (currently Docker
    # containers and Windows VMs) and is a no-op otherwise.
    await clear_core_dumps(connection)
