import asyncio
import os
from dataclasses import dataclass
from tests.utils.connection import Connection
from tests.utils.connection_util import get_uniffi_path
from tests.utils.logger import log
from tests.utils.testing import get_current_test_log_path
from typing import Optional

FLAME_GRAPH_FILE = "connect_node_flamegraph.svg"
FLAME_GRAPH_FILE_WITH_PYTHON = "connect_node_flamegraph_with_python.svg"
TEMP_DEBUG_SYMBOLS_FOLDER = "/tmp/libtelio_debug"
PERF_OUTPUT_FILE = "perf_cpu_clock.data"
PERF_OUTPUT_PATH = f"/tmp/{PERF_OUTPUT_FILE}"
PERF_CMD = [
    "perf",
    "record",
    "-F",
    "999",
    "-g",
    "--call-graph",
    "dwarf",
    "-e",
    "cpu-clock",
    "-o",
    PERF_OUTPUT_PATH,
    "--",
]


@dataclass
class PerfProfiler:
    """
    Handles performance profiling with perf and flame graph generation.

    # Attributes

    * connection - Connection to the instance where perf is running
    * output_dir - Directory to save results to. If None, uses current test log path.
    """

    connection: Connection
    output_dir: Optional[str] = None

    async def __aenter__(self) -> "PerfProfiler":
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb) -> bool:
        await self.setup_debug_symbols()
        await self.wait_for_completion()
        await self.generate_flame_graphs()
        await self.save_results()
        return False

    async def wait_for_completion(self) -> None:
        """Wait for perf recording to finish."""
        while True:
            procs = await self.connection.create_process(
                ["ps", "aux"],
                quiet=True,
            ).execute()
            processes = procs.get_stdout().strip()
            if not any("perf record" in line for line in processes.splitlines()):
                break
            await asyncio.sleep(1)

    async def setup_debug_symbols(self) -> None:
        """Set up debug symbols for perf profiling of libtelio.so."""
        uniffi_dir = os.path.dirname(get_uniffi_path(self.connection))
        log.info("Add a GNU Debug Link to the Stripped Binary")
        libtelio_debug_path = os.path.join(
            TEMP_DEBUG_SYMBOLS_FOLDER, uniffi_dir.lstrip("/")
        )
        await self.connection.create_process(
            ["sh", "-c", f"mkdir -p {libtelio_debug_path}"]
        ).execute()
        await self.connection.create_process([
            "sh",
            "-c",
            f"cp {uniffi_dir}/libtelio.so {libtelio_debug_path}/libtelio.so",
        ]).execute()
        await self.connection.create_process([
            "sh",
            "-c",
            f"cp {uniffi_dir}/libtelio.so.debug {libtelio_debug_path}/libtelio.so.debug",
        ]).execute()
        await self.connection.create_process([
            "sh",
            "-c",
            f"objcopy --add-gnu-debuglink={libtelio_debug_path}/libtelio.so.debug {libtelio_debug_path}/libtelio.so",
        ]).execute()

    async def generate_flame_graphs(self) -> None:
        """Generate flame graph charts from perf data."""
        log.info("Generating flame graph charts")

        cmd_filtered = (
            f"perf script --demangle -i {PERF_OUTPUT_PATH} --symfs {TEMP_DEBUG_SYMBOLS_FOLDER} | "
            f"stackcollapse-perf.pl | egrep '(tokio|libtelio|telio|neptun)' | "
            f"flamegraph.pl > /tmp/{FLAME_GRAPH_FILE}"
        )
        await self.connection.create_process(["sh", "-c", cmd_filtered]).execute()

        cmd_full = (
            f"perf script --demangle -i {PERF_OUTPUT_PATH} --symfs {TEMP_DEBUG_SYMBOLS_FOLDER} | "
            f"stackcollapse-perf.pl | flamegraph.pl > /tmp/{FLAME_GRAPH_FILE_WITH_PYTHON}"
        )
        await self.connection.create_process(["sh", "-c", cmd_full]).execute()

    async def save_results(self) -> None:
        """Download perf data and flame graphs to local directory."""
        log_dir = self.output_dir or get_current_test_log_path()
        os.makedirs(log_dir, exist_ok=True)

        log.info("Saving results to logs in %s", log_dir)

        perf_local_path = os.path.join(log_dir, PERF_OUTPUT_FILE)
        graph_path = os.path.join(log_dir, FLAME_GRAPH_FILE)
        graph_path_with_python = os.path.join(log_dir, FLAME_GRAPH_FILE_WITH_PYTHON)

        await self.connection.download(PERF_OUTPUT_PATH, perf_local_path)
        await self.connection.download(f"/tmp/{FLAME_GRAPH_FILE}", graph_path)
        await self.connection.download(
            f"/tmp/{FLAME_GRAPH_FILE_WITH_PYTHON}", graph_path_with_python
        )
