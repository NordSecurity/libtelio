import os
from asyncio import Event
from config import WINDUMP_BINARY_WINDOWS
from contextlib import asynccontextmanager, AsyncExitStack
from typing import AsyncIterator, Optional, List
from utils.connection import TargetOS, Connection
from utils.output_notifier import OutputNotifier
from utils.process import Process
from utils.testing import get_current_test_log_path

PCAP_FILE_PATH = {
    TargetOS.Linux: "/dump.pcap",
    TargetOS.Mac: "/tmp/dump.pcap",
    TargetOS.Windows: "C:\\workspace\\dump.pcap",
}


class TcpDump:
    interfaces: Optional[List[str]]
    connection: Connection
    process: Process
    stdout: str
    stderr: str
    output_file: Optional[str]
    output_notifier: OutputNotifier
    count: Optional[int]

    def __init__(
        self,
        connection: Connection,
        filters: List[str],
        interfaces: Optional[List[str]] = None,
        output_file: Optional[str] = None,
        count: Optional[int] = None,
    ) -> None:
        self.connection = connection
        self.interfaces = interfaces
        self.output_file = output_file
        self.output_notifier = OutputNotifier()
        self.start_event = Event()
        self.count = count
        self.stdout = ""
        self.stderr = ""

        self.output_notifier.notify_output("listening on", self.start_event)

        command = [
            self.get_tcpdump_binary(connection.target_os),
            "-l",
        ]

        if self.output_file:
            command += ["-w", self.output_file]
        else:
            command += ["-w", PCAP_FILE_PATH[self.connection.target_os]]

        if self.interfaces:
            for interface in self.interfaces:
                command += ["-i", interface]
        else:
            if self.connection.target_os != TargetOS.Windows:
                command += ["-i", "any"]
            else:
                command += ["-i", "1", "-i", "2"]

        if self.connection.target_os != TargetOS.Windows:
            command += ["--immediate-mode"]

        if self.count:
            command += ["-c", self.count]

        command += filters

        self.process = self.connection.create_process(command)

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
        await self.output_notifier.handle_output(output)

    async def on_stderr(self, output: str) -> None:
        self.stderr += output
        await self.output_notifier.handle_output(output)

    async def execute(self) -> None:
        try:
            await self.process.execute(self.on_stdout, self.on_stderr, True)
        except Exception as e:
            print(f"Error executing tcpdump: {e}")
            raise

    @asynccontextmanager
    async def run(self) -> AsyncIterator["TcpDump"]:
        async with self.process.run(self.on_stdout, self.on_stderr, True):
            await self.start_event.wait()
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
    try:
        async with AsyncExitStack() as exit_stack:
            for conn in connection_list:
                await exit_stack.enter_async_context(TcpDump(conn, ["-U"]).run())
            yield
    finally:
        if download:
            log_dir = get_current_test_log_path()
            os.makedirs(log_dir, exist_ok=True)
            for conn in connection_list:
                path = find_unique_path_for_tcpdump(
                    store_in if store_in else log_dir, conn.target_name()
                )
                await conn.download(PCAP_FILE_PATH[conn.target_os], path)
