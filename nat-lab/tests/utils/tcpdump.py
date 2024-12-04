import os
from config import WINDUMP_BINARY_WINDOWS
from contextlib import asynccontextmanager, AsyncExitStack
from typing import AsyncIterator, Optional, List
from utils.connection import TargetOS, Connection
from utils.process import Process
from utils.testing import get_current_test_log_path

PCAP_FILE_PATH = "/dump.pcap"


class TcpDump:
    interface: str
    connection: Connection
    process: Process
    verbose: bool
    stdout: str
    stderr: str
    output_file: str

    def __init__(
        self,
        connection: Connection,
        filters: List[str],
        interface: str = "any",
        output_file: str = PCAP_FILE_PATH,
        verbose: bool = False,
    ) -> None:
        self.connection = connection
        self.interface = interface
        self.output_file = output_file
        self.process = self.connection.create_process(
            [
                self.get_tcpdump_binary(connection.target_os),
                "-i",
                self.interface,
                "-w",
                self.output_file,
            ]
            + filters
        )
        self.verbose = verbose
        self.stdout = ""
        self.stderr = ""

    @staticmethod
    def get_tcpdump_binary(target_os: TargetOS) -> str:
        if target_os in [TargetOS.Linux, TargetOS.Mac]:
            return "tcpdump"

        if target_os == TargetOS.Windows:
            return WINDUMP_BINARY_WINDOWS

        raise ValueError(f"target_os not supported {target_os}")

    def get_stdout(self) -> str:
        return self.stdout

    def get_stderr(self) -> str:
        return self.stderr

    async def on_stdout(self, output: str) -> None:
        self.stdout += output
        if self.verbose:
            print(f"TCPDUMP: {output}")

    async def on_stderr(self, output: str) -> None:
        self.stderr += output
        if self.verbose:
            print(f"TCPDUMP ERROR: {output}")

    async def execute(self) -> None:
        try:
            await self.process.execute(self.on_stdout, self.on_stderr, True)
        except Exception as e:
            print(f"Error executing tcpdump: {e}")
            raise

    @asynccontextmanager
    async def run(self) -> AsyncIterator["TcpDump"]:
        async with self.process.run(self.on_stdout, self.on_stderr, True):
            yield self


def find_unique_path_for_tcpdump(log_dir, guest_name):
    candidate_path = f"{log_dir}/{guest_name}.pcap"
    counter = 1
    # NOTE: counter starting from '1' means that the file will either have no suffix or
    # will have a suffix starting from '2'. This is to make it clear that it's not the
    # first log for that guest/client.
    while os.path.isfile(candidate_path):
        counter += 1
        candidate_path = f"./{log_dir}/{guest_name}-{counter}.pcap"
    return candidate_path


@asynccontextmanager
async def make_tcpdump(
    connection_list: list[Connection],
    download: bool = True,
    store_in: Optional[str] = None,
):
    async with AsyncExitStack() as exit_stack:
        for conn in connection_list:
            await exit_stack.enter_async_context(
                TcpDump(conn, ["-U"], verbose=True).run()
            )
        try:
            yield
        finally:
            if download:
                log_dir = get_current_test_log_path()
                os.makedirs(log_dir, exist_ok=True)
                for conn in connection_list:
                    path = find_unique_path_for_tcpdump(
                        store_in if store_in else log_dir, conn.target_name()
                    )
                    await conn.download(PCAP_FILE_PATH, path)
