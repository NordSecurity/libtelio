import typing
from contextlib import asynccontextmanager
from enum import Enum
from scapy.all import PcapReader  # type: ignore
from scapy.layers.inet import IP, ICMP  # type: ignore
from typing import AsyncIterator
from utils.connection_util import ConnectionTag, new_connection_raw, container_id


class TargetMachine:
    def __init__(self, tag: ConnectionTag):
        self.tag = tag
        self.container_id = container_id(tag)

    def __repr__(self):
        return f"TargetMachine({self.tag})"


class Histogram:
    def __init__(self) -> None:
        self._values: typing.List[float] = []

    def add_value(self, value: float) -> None:
        self._values.append(value)

    def get(self, bin_count: int, bin_width: int):
        sorted_values = sorted(self._values)
        max_val = sorted_values[len(sorted_values) - 1]

        if max_val >= bin_count * bin_width:
            raise ValueError(
                f"Histogram doesn't fit value of {max_val}. Has {bin_count} with width of"
                f" {bin_width}"
            )

        hs = [0] * bin_count
        start = 0

        for v in sorted_values:
            bin_index = int((v - start) / bin_width)
            hs[bin_index] += 1

        return hs

    def __repr__(self) -> str:
        return f"Histogram of {len(self._values)} values"


class Direction(Enum):
    Incoming = 1
    Outgoing = 2


class ObservationTarget:
    def __init__(self, direction: Direction, dir_ip: str):
        self.dir = direction
        self.ip = dir_ip

    def __repr__(self):
        return f"ObservationTarget({self.dir}, {self.ip})"


# BatchObserver launches tcpdump inside of the container and captures all of the traffic
class BatchObserver:
    def __init__(self, target: TargetMachine):
        self._target = target

    async def on_stdout(self, line: str) -> None:
        print(f"Batch observer stdout: {line}")

    async def on_stderr(self, line: str) -> None:
        print(f"Batch observer stderr: {line}")

    # TCPdump is used to packet capture. However interfaces need to test  carefully
    # selected to listen on. Listening on non-existing interface will immediately
    # fail the tcpdump(if tunnel interface appears only after a delay), then a delay is needed
    # to combat this, however that is not that deterministic.
    @asynccontextmanager
    async def run(self, iface: str = "tun10") -> AsyncIterator["BatchObserver"]:
        async with new_connection_raw(self._target.tag) as conn:
            proc = conn.create_process([
                "tcpdump",
                "-U",
                "-l",
                "-n",
                "-i",
                f"{iface}",
                "-w",
                f"./{self._target.tag}.pcap",
            ])

            async with proc.run(
                stdout_callback=self.on_stdout, stderr_callback=self.on_stderr
            ):
                yield self

    # TODO: this doesn't respect ipv6
    def get_histogram(
        self, hs_bins: int, hs_bin_width: int, target: ObservationTarget
    ) -> typing.List[int]:
        filepath = f"./{self._target.tag}.pcap"
        print("Looking for a pcap at", filepath)

        total_time_ms = 0
        hist = Histogram()

        def is_icmp_echo_request(pkt):
            return (
                pkt.haslayer(ICMP) and pkt[ICMP].type == 8
            )  # ICMP type 8 is echo request

        with PcapReader(filepath) as pcap_reader:
            last_pkt_time = None
            last_pkt = None

            for pkt in pcap_reader:
                if not pkt.haslayer(IP):
                    continue

                if not is_icmp_echo_request(pkt):
                    continue
                src = pkt[IP].src
                dst = pkt[IP].dst

                if target.dir == Direction.Incoming:
                    if dst != target.ip:
                        continue
                elif target.dir == Direction.Outgoing:
                    if src != target.ip:
                        continue
                else:
                    raise ValueError("Bad target direction")

                if last_pkt_time is None:
                    last_pkt_time = pkt.time
                else:
                    last_pkt_time = last_pkt.time
                last_pkt = pkt

                tdelta_ms = (pkt.time - last_pkt_time) * 1000

                assert tdelta_ms >= 0
                total_time_ms += tdelta_ms
                # Uncomment to dump the packets that are used in histogram
                # print(
                #     pkt.time,
                #     total_time_ms,
                #     f"tdelta: {tdelta_ms}",
                #     pkt.summary(),
                #     "for",
                #     target,
                # )
                hist.add_value(tdelta_ms)

        return hist.get(hs_bins, hs_bin_width)
