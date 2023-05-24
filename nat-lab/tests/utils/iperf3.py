from utils.connection import Connection, TargetOS
from utils.process import Process
from utils.asyncio_util import (
    cancel_future,
    run_async,
)
from typing import Optional, Coroutine
from utils import OutputNotifier
from asyncio import Event, sleep
from enum import Enum, auto
import config
import re


class Protocol(Enum):
    Tcp = auto()
    Udp = auto()


def get_iperf_binary(target_os: TargetOS) -> str:
    if target_os == TargetOS.Linux:
        return "iperf3"

    elif target_os == TargetOS.Windows:
        return config.IPERF_BINARY_WINDOWS

    elif target_os == TargetOS.Mac:
        return config.IPERF_BINARY_MAC

    else:
        assert False, f"target_os not supported {target_os}"


class IperfServer:
    _process: Process
    _stop: Optional[Coroutine]
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
        self._stop = None
        self._log_prefix = log_prefix
        self._stdout = ""
        self._output_notifier = OutputNotifier()
        self._verbose = verbose
        self._process = connection.create_process(
            [
                get_iperf_binary(connection.target_os),
                "-s",
                "-f",
                "k",
                "-i",
                "1",
                "" if protocol == Protocol.Tcp else "--udp-counters-64bit",
            ]
        )

    def get_stdout(self) -> str:
        return self._stdout

    async def listening_started(self) -> None:
        event = Event()
        self._output_notifier.notify_output("Server listening on 5201", event)
        await event.wait()

    async def stop(self) -> None:
        if self._stop:
            await self._stop
            self._stop = None

    async def __aenter__(self) -> "IperfServer":
        async def on_stdout(stdout: str) -> None:
            self._stdout += stdout
            for line in stdout.splitlines():
                self._output_notifier.handle_output(line)
                if self._verbose:
                    print(f"[{self._log_prefix}] - Server: {line}")

        process_future = run_async(self._process.execute(stdout_callback=on_stdout))

        async def stop() -> None:
            await cancel_future(process_future)

        self._stop = stop()

        await sleep(1)

        return self

    async def __aexit__(self, exc_type, exc, tb):
        await self.stop()


class IperfClient:
    _stop: Optional[Coroutine]
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
        self._stop = None
        self._log_prefix = log_prefix
        self._stdout = ""
        self._output_notifier = OutputNotifier()
        self._verbose = verbose
        self._connection = connection
        self._send = send
        self._protocol = protocol
        self._transmit_time = transmit_time
        self._process = connection.create_process(
            [
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
                "" if send == True else "-R",
            ]
        )

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

    async def stop(self) -> None:
        if self._stop:
            await self._stop
            self._stop = None

    async def __aenter__(self) -> "IperfClient":
        async def on_stdout(stdout: str) -> None:
            self._output_notifier.handle_output(stdout)
            self._stdout += stdout
            for line in stdout.splitlines():
                if self._verbose:
                    print(f"[{self._log_prefix}] - Client: {line}")

        process_future = run_async(self._process.execute(stdout_callback=on_stdout))

        async def stop() -> None:
            await cancel_future(process_future)

        self._stop = stop()

        return self

    async def __aexit__(self, exc_type, exc, tb):
        await self.stop()
