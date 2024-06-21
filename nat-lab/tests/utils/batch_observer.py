import asyncio
import scapy.all as scapy
import typing
from contextlib import asynccontextmanager
from typing import AsyncIterator
from utils.connection import Connection


class Histogram:
    def __init__(self, bins: int) -> None:
        self._values = []
        self._bins = bins

    def add_value(self, value: float) -> None:
        self._values.append(value)

    def _histogram(self, bin_width=1):
        sorted_values = sorted(self._values)
        min, max = sorted_values[0], sorted_values[len(sorted_values) - 1]

        start = min

        if max >= self._bins * bin_width:
            raise ValueError(
                f"Histogram doesn't fit value of {max}. Has {self._bins} with width of {bin_width}"
            )

        hs = [0] * (self._bins + 1)

        for v in sorted_values:
            bin_index = int((v - start) / bin_width)
            hs[bin_index] += 1

        return hs

    def bins(self) -> typing.List[int]:
        return self._histogram()

    def __repr__(self) -> str:
        return f"Histogram of {len(self._values)} values"


class EventCollection:
    def __init__(self) -> None:
        self._events: typing.List[Event] = []

    def add_event(self, event: "Event") -> None:
        self._events.append(event)

    def get_histogram(self, hs_buckets) -> Histogram:
        histogram = Histogram(hs_buckets)
        for event in self._events:
            histogram.add_value(event._timestamp)
        return histogram


# tcpdump ioutgoing event
class Event:
    _timestamp: float
    _src_ip: str
    _dst_ip: str

    def __init__(self, timestamp: float, src_ip: str, dst_ip: str) -> None:
        self._timestamp = timestamp
        self._src_ip = src_ip
        self._dst_ip = dst_ip

    def __repr__(self) -> str:
        return (
            f"Event(timestamp={self._timestamp}, src_ip={self._src_ip},"
            f" dst_ip={self._dst_ip})"
        )


class Direction:
    Both = 0
    Incoming = 1
    Outgoing = 2


class ObservationTarget:
    def __init__(self, dir: Direction, dir_ip: str):
        self.dir = dir
        self.ip = dir_ip


# BatchObserver launches tcpdump inside of the container and captures all of the traffic
class BatchObserver:
    def __init__(
        self,
        name: str,
        connection: Connection,
    ) -> None:
        self._events: typing.List[Event] = []
        self._name = name
        self._connection = connection

    async def on_stdout(self, line: str) -> None:
        print(f"Batch observer stdout: {line}")

    async def on_stderr(self, line: str) -> None:
        print(f"Batch observer stderr: {line}")

    async def execute(self) -> None:
        try:
            async with self._process.run(
                stdout_callback=self.on_stdout, stderr_callback=self.on_stderr
            ):
                await asyncio.sleep(self._duration_s)
        except asyncio.CancelledError as e:
            pass
        finally:
            pass

    @asynccontextmanager
    async def run(self, iface: str = "eth0") -> AsyncIterator["BatchObserver"]:
        if self._connection is None:
            raise ValueError("Connection is not set. Batcher cannot run without it.")
        self._process = self._connection.create_process([
            "tcpdump",
            "-l",
            "-n",
            "-i",
            f"{iface}",
            "-w",
            f"/libtelio/{self._name}.pcap",
            "-Z",
            "root",
        ])

        async with self._process.run(
            stdout_callback=self.on_stdout, stderr_callback=self.on_stderr
        ):
            yield self

    def get_histogram(
        self, hs_buckets: int, target: ObservationTarget
    ) -> EventCollection:
        assert hs_buckets > 0

        filepath = f"./{self._name}.pcap"

        total_time = 0
        evc = EventCollection()
        with scapy.PcapReader(filepath) as pcap_reader:
            last_pkt_time = None
            last_pkt = None

            for pkt in pcap_reader:
                if not pkt.haslayer(scapy.IP):
                    continue

                src = pkt[scapy.IP].src
                dst = pkt[scapy.IP].dst

                if target.dir == Direction.Incoming:
                    if dst != target.ip:
                        continue
                elif target.dir == Direction.Outgoing:
                    if src != target.ip:
                        continue
                else:
                    if src != target.ip and dst != target.ip:
                        continue

                if last_pkt_time is None:
                    last_pkt_time = pkt.time
                else:
                    last_pkt_time = last_pkt.time
                last_pkt = pkt

                tdelta = pkt.time - last_pkt_time
                # print(pkt.time, total_time, direction, f"tdelta: {tdelta}", pkt.summary(), pkt.time, pkt.time)

                assert tdelta >= 0
                total_time += tdelta
                if total_time > 100 or True:
                    evc.add_event(Event(tdelta, src, dst))
        return evc.get_histogram(hs_buckets)
