import re
from asyncio import Event
from contextlib import asynccontextmanager
from enum import Enum, auto
from tests.config import IPERF_BINARY_MAC, IPERF_BINARY_WINDOWS
from tests.utils.connection import Connection, TargetOS
from tests.utils.logger import log
from tests.utils.output_notifier import OutputNotifier
from tests.utils.process import Process
from typing import AsyncIterator


class Protocol(Enum):
    Tcp = auto()
    Udp = auto()


def get_iperf_binary(target_os: TargetOS) -> str:
    if target_os == TargetOS.Linux:
        return "iperf3"

    if target_os == TargetOS.Windows:
        return IPERF_BINARY_WINDOWS

    if target_os == TargetOS.Mac:
        return IPERF_BINARY_MAC

    assert False, f"target_os not supported {target_os}"


class IperfServer:
    _process: Process
    _stdout: str
    _log_prefix: str
    _output_notifier: OutputNotifier
    _verbose: bool

    def __init__(
        self,
        connection: Connection,
        log_prefix: str,
        verbose: bool = False,
        protocol: Protocol = Protocol.Udp,
    ) -> None:
        self._log_prefix = log_prefix
        self._stdout = ""
        self._output_notifier = OutputNotifier()
        self._verbose = verbose
        self._process = connection.create_process([
            get_iperf_binary(connection.target_os),
            "-s",
            "-f",
            "k",
            "-i",
            "1",
            "" if protocol == Protocol.Tcp else "--udp-counters-64bit",
        ])

    def get_stdout(self) -> str:
        return self._stdout

    async def listening_started(self) -> None:
        event = Event()
        self._output_notifier.notify_output("Server listening on 5201", event)
        await event.wait()

    async def on_stdout(self, stdout: str) -> None:
        await self._output_notifier.handle_output(stdout)
        self._stdout += stdout
        for line in stdout.splitlines():
            if self._verbose:
                log.info("[%s] - Server: %s", self._log_prefix, line)

    async def execute(self) -> None:
        await self._process.execute(stdout_callback=self.on_stdout)

    @asynccontextmanager
    async def run(self) -> AsyncIterator["IperfServer"]:
        async with self._process.run(stdout_callback=self.on_stdout):
            yield self


class IperfClient:
    _process: Process
    _stdout: str
    _log_prefix: str
    _output_notifier: OutputNotifier
    _verbose: bool
    _connection: Connection
    _send: bool
    _transmit_time: int
    _protocol: Protocol

    def __init__(
        self,
        server_ip: str,
        connection: Connection,
        log_prefix: str,
        transmit_time: int,
        buf_length: int,
        verbose: bool = False,
        protocol: Protocol = Protocol.Udp,
        send: bool = True,
    ):
        self._log_prefix = log_prefix
        self._stdout = ""
        self._output_notifier = OutputNotifier()
        self._verbose = verbose
        self._connection = connection
        self._send = send
        self._protocol = protocol
        self._transmit_time = transmit_time
        self._process = connection.create_process([
            get_iperf_binary(connection.target_os),
            "-c",
            server_ip,
            "-t",
            f"{transmit_time}s",
            "-l",
            f"{buf_length}",
            "-i",
            "1",
            "-f",
            "k",
            "" if protocol == Protocol.Tcp else "-u",
            "" if protocol == Protocol.Tcp else "--udp-counters-64bit",
            "-b",
            "10G",
            "" if send else "-R",
        ])

    async def done(self) -> None:
        event = Event()
        self._output_notifier.notify_output("iperf Done.", event)
        await event.wait()

    def get_stdout(self) -> str:
        return self._stdout

    def get_speed(self) -> int:
        regex_string = r"0\.00-" + str(self._transmit_time) + r".* (\d+) Kbits\/sec*"
        if self._protocol is Protocol.Tcp:
            if self._send is True:
                regex_string = (
                    r"0\.00-"
                    + str(self._transmit_time)
                    + r".* (\d+) Kbits\/sec.+?(?=sender)"
                )
            else:
                regex_string = (
                    r"0\.00-"
                    + str(self._transmit_time)
                    + r".* (\d+) Kbits\/sec.+?(?=receiver)"
                )

        match = re.search(regex_string, self._stdout)
        assert match
        return int(match.group(1))

    async def on_stdout(self, stdout: str) -> None:
        await self._output_notifier.handle_output(stdout)
        self._stdout += stdout
        for line in stdout.splitlines():
            if self._verbose:

                log.info("[%s] - Client: %s", self._log_prefix, line)

    async def execute(self) -> None:
        await self._process.execute(stdout_callback=self.on_stdout)

    @asynccontextmanager
    async def run(self) -> AsyncIterator["IperfClient"]:
        async with self._process.run(stdout_callback=self.on_stdout):
            yield self
