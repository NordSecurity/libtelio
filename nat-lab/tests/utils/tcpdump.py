from config import WINDUMP_BINARY_WINDOWS
from contextlib import asynccontextmanager
from typing import AsyncIterator, Optional, List
from utils.connection import TargetOS, Connection
from utils.process import Process

PCAP_FILE_PATH = "/dump.pcap"


class TcpDump:
    interface: str
    protocol: str
    connection: Connection
    process: Process
    verbose: bool
    stdout: str
    stderr: str
    file: str

    def __init__(
        self,
        connection: Connection,
        interface: Optional[str],
        protocol: Optional[str],
        file: Optional[str],
        flags: List[str],
    ) -> None:
        self.connection = connection
        self.interface = interface or "any"
        self.protocol = protocol or "any"
        self.file = file or PCAP_FILE_PATH
        self.process = self.connection.create_process(
            [
                self.get_tcpdump_binary(connection.target_os),
                f"-i {self.interface}",
                f"-w {self.file}",
            ]
            + flags
        )

    @staticmethod
    def get_tcpdump_binary(target_os: TargetOS) -> str:
        if target_os in [TargetOS.Linux, TargetOS.Mac]:
            return "tcpdump"

        if target_os == TargetOS.Windows:
            return WINDUMP_BINARY_WINDOWS

        assert False, f"target_os not supported {target_os}"

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
        await self.process.execute(self.on_stdout, self.on_stderr)

    @asynccontextmanager
    async def run(self) -> AsyncIterator["TcpDump"]:
        async with self.process.run(self.on_stdout, self.on_stderr):
            yield self
