import json
import re
from asyncio import Event
from contextlib import asynccontextmanager
from enum import Enum, auto
from tests.config import IPERF_BINARY_MAC, IPERF_BINARY_WINDOWS
from tests.utils.connection import Connection, TargetOS
from tests.utils.logger import log
from tests.utils.output_notifier import OutputNotifier
from tests.utils.process import Process
from typing import AsyncIterator, Any, Dict


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
        force_flush: bool = True,
        output_unit: str = "k",
    ) -> None:
        self._log_prefix = log_prefix
        self._stdout = ""
        self._output_notifier = OutputNotifier()
        self._verbose = verbose
        self._process = connection.create_process([
            get_iperf_binary(connection.target_os),
            "--forceflush" if force_flush else "",
            "-s",
            "-f",
            f"{output_unit}",
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
    _json_enabled: bool
    _json_data: Dict[str, Any] | None

    def __init__(
        self,
        server_ip: str,
        connection: Connection,
        log_prefix: str,
        transmit_time: int,
        buf_length: str,
        verbose: bool = False,
        protocol: Protocol = Protocol.Udp,
        send: bool = True,
        output_unit: str = "k",
        json_output: bool = False,
    ):
        self._json_enabled = json_output
        self._json_data = None
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
            f"{output_unit}",
            "" if protocol == Protocol.Tcp else "-u",
            "" if protocol == Protocol.Tcp else "--udp-counters-64bit",
            "-b",
            "10G",
            "" if send else "-R",
            "--json" if json_output else "",
        ])

    async def done(self) -> None:
        await self._process.is_done()
        if self._json_enabled:
            self._json_data = json.loads(self._stdout)

    def get_stdout(self) -> str:
        return self._stdout

    def get_speed(self, unit: str = "Kbits") -> int:
        if self._json_enabled:
            assert self._json_data, "JSON data not parsed yet"

            if self._protocol is Protocol.Tcp:
                if self._send:
                    bps = self._json_data["end"]["streams"][0]["sender"][
                        "bits_per_second"
                    ]
                else:
                    bps = self._json_data["end"]["streams"][0]["receiver"][
                        "bits_per_second"
                    ]
            else:
                bps = self._json_data["end"]["sum"]["bits_per_second"]

            if unit.lower().startswith("mbit"):
                return int(bps / 1_000_000)
            if unit.lower().startswith("kbit"):
                return int(bps / 1_000)
            raise ValueError("Unsupported unit: " + unit)

        unit_escaped = re.escape(unit)
        if self._protocol is Protocol.Tcp:
            if self._send:
                regex_string = rf"0\.00-{self._transmit_time}.* (\d+) {unit_escaped}/sec.+?(?=sender)"
            else:
                regex_string = rf"0\.00-{self._transmit_time}.* (\d+) {unit_escaped}/sec.+?(?=receiver)"
        else:
            regex_string = rf"0\.00-{self._transmit_time}.* (\d+) {unit_escaped}/sec*"

        match = re.search(regex_string, self._stdout)
        assert match, f"No match found for unit {unit}"
        return int(match.group(1))

    def get_retransmits(self) -> int:
        if not self._json_enabled:
            raise RuntimeError("Retransmit parsing is only supported in JSON mode.")

        if self._json_data is None:
            raise RuntimeError("JSON output not parsed yet. Call done() first.")

        if self._protocol is not Protocol.Tcp:
            raise RuntimeError("Retransmits only exist in TCP mode.")

        if not self._send:
            raise RuntimeError("Retransmit count is not available in reverse mode (-R)")

        stream = self._json_data["end"]["streams"][0]
        return stream["sender"].get("retransmits", 0)

    def get_rtt_stats(self) -> tuple[float, float, float]:
        if not self._json_enabled:
            raise RuntimeError("RTT statistics are only supported in JSON mode.")

        if self._json_data is None:
            raise RuntimeError("JSON output not parsed yet. Call done() first.")

        if self._protocol is not Protocol.Tcp:
            raise RuntimeError("RTT statistics only exist in TCP mode.")

        sender = self._json_data["end"]["streams"][0]["sender"]

        # JSON iperf3 stores RTT in microseconds
        # Converting to milliseconds
        min_rtt = sender.get("min_rtt", 0) / 1000.0
        max_rtt = sender.get("max_rtt", 0) / 1000.0
        mean_rtt = sender.get("mean_rtt", 0) / 1000.0
        return min_rtt, max_rtt, mean_rtt

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
