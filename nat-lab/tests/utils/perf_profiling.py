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
FOLDED_STACKS_FILE = "connect_node_folded_stacks.txt"
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
    "-k",
    "CLOCK_MONOTONIC",
    "-o",
    PERF_OUTPUT_PATH,
    "--",
]
PERF_ROUNDS_PATH = "/tmp/perf_rounds.txt"  # "start end" per line, CLOCK_MONOTONIC seconds


@dataclass
class PerfProfiler:
    """
    Handles performance profiling with perf and flame graph generation.

    # Attributes

    * connection - Connection to the instance where perf is running
    * output_dir - Directory to save results to. If None, uses current test log path.
    * file_name_suffix - Optional suffix inserted before the extension of saved
      artifact file names (e.g. adapter type), so results from parametrized runs
      do not collide.
    """

    connection: Connection
    output_dir: Optional[str] = None
    file_name_suffix: Optional[str] = None

    def _apply_suffix(self, file_name: str) -> str:
        if not self.file_name_suffix:
            return file_name
        name, ext = os.path.splitext(file_name)
        return f"{name}_{self.file_name_suffix}{ext}"

    @property
    def flame_graph_file(self) -> str:
        return self._apply_suffix(FLAME_GRAPH_FILE)

    @property
    def flame_graph_file_with_python(self) -> str:
        return self._apply_suffix(FLAME_GRAPH_FILE_WITH_PYTHON)

    @property
    def folded_stacks_file(self) -> str:
        return self._apply_suffix(FOLDED_STACKS_FILE)

    @property
    def perf_output_file(self) -> str:
        return self._apply_suffix(PERF_OUTPUT_FILE)

    async def __aenter__(self) -> "PerfProfiler":
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb) -> bool:
        await self.setup_debug_symbols()
        await self.wait_for_completion()
        await self.generate_flame_graphs()
        round_files = await self.generate_round_folded_stacks()
        await self.save_results(round_files)
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
        """Generate flame graph charts and folded stacks from perf data."""
        log.info("Generating flame graph charts")

        cmd_filtered = (
            f"perf script --demangle -i {PERF_OUTPUT_PATH} --symfs {TEMP_DEBUG_SYMBOLS_FOLDER} | "
            f"stackcollapse-perf.pl | egrep '(tokio|libtelio|telio|neptun)' | "
            f"tee /tmp/{self.folded_stacks_file} | "
            f"flamegraph.pl > /tmp/{self.flame_graph_file}"
        )
        await self.connection.create_process(["sh", "-c", cmd_filtered]).execute()

        cmd_full = (
            f"perf script --demangle -i {PERF_OUTPUT_PATH} --symfs {TEMP_DEBUG_SYMBOLS_FOLDER} | "
            f"stackcollapse-perf.pl | flamegraph.pl > /tmp/{self.flame_graph_file_with_python}"
        )
        await self.connection.create_process(["sh", "-c", cmd_full]).execute()

    async def generate_round_folded_stacks(self) -> list[str]:
        """One folded file per round listed in PERF_ROUNDS_PATH, if the test wrote it."""
        out = await self.connection.create_process(
            ["sh", "-c", f"cat {PERF_ROUNDS_PATH} 2>/dev/null || true"], quiet=True
        ).execute()
        files = []
        for i, line in enumerate(
            l for l in out.get_stdout().splitlines() if l.strip()
        ):
            start, end = line.split()
            name = self._apply_suffix(f"connect_node_folded_stacks_r{i:02d}.txt")
            cmd = (
                f"perf script --demangle -i {PERF_OUTPUT_PATH} --symfs {TEMP_DEBUG_SYMBOLS_FOLDER}"
                f" --time {start},{end} | stackcollapse-perf.pl"
                f" | egrep '(tokio|libtelio|telio|neptun)' > /tmp/{name}"
            )
            await self.connection.create_process(["sh", "-c", cmd]).execute()
            files.append(name)
        return files

    async def save_results(self, round_files: Optional[list[str]] = None) -> None:
        """Download perf data, flame graphs, and folded stacks to local directory."""
        log_dir = self.output_dir or get_current_test_log_path()
        os.makedirs(log_dir, exist_ok=True)

        log.info("Saving results to logs in %s", log_dir)

        perf_local_path = os.path.join(log_dir, self.perf_output_file)
        graph_path = os.path.join(log_dir, self.flame_graph_file)
        graph_path_with_python = os.path.join(
            log_dir, self.flame_graph_file_with_python
        )
        folded_stacks_path = os.path.join(log_dir, self.folded_stacks_file)

        await self.connection.download(PERF_OUTPUT_PATH, perf_local_path)
        await self.connection.download(f"/tmp/{self.flame_graph_file}", graph_path)
        await self.connection.download(
            f"/tmp/{self.flame_graph_file_with_python}", graph_path_with_python
        )
        await self.connection.download(
            f"/tmp/{self.folded_stacks_file}", folded_stacks_path
        )
        for name in round_files or []:
            await self.connection.download(f"/tmp/{name}", os.path.join(log_dir, name))
