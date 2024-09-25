import asyncio
import math
import os
import pytest
import subprocess
import tempfile
import typing
from scapy.all import PcapReader, Packet  # type: ignore
from typing import Callable, List, Optional


def _generate_histogram(
    data: list[int], buckets: int, bucket_size: int = 1
) -> List[int]:
    assert len(data) > 0
    max_val = max(data)

    if max_val >= buckets * bucket_size:
        raise ValueError(
            f"Histogram doesn't fit the data({max_val}). The max value is {max_val} but the histogram has {buckets} buckets with a width of"
            f" {bucket_size}, the maximum value it can fit is {buckets * bucket_size}"
        )

    hs = [0] * buckets

    for v in data:
        bucket_index = int(v / bucket_size)
        hs[bucket_index] += 1

    return hs


async def capture_traffic(container_name: str, duration_s: int) -> str:
    iface = "any"
    capture_path = "/home/capture.pcap"

    cmd = f"docker exec -d --privileged {container_name} tcpdump -i {iface} -U -w {capture_path}"
    res = os.system(cmd)
    if res != 0:
        raise RuntimeError(f"Failed to launch tcpdump on {container_name}")

    await asyncio.sleep(duration_s)

    local_path = f"{tempfile.mkstemp(suffix='.pcap')[1]}"
    print(f"Copying pcap to {local_path}")
    subprocess.run([
        "docker",
        "cp",
        container_name + ":" + "/home/capture.pcap",
        local_path,
    ])

    cmd_rm = f"docker exec --privileged {container_name} pkill tcpdump"
    os.system(cmd_rm)

    return local_path


# Render ASCII histogram drawing for visual inspection
def print_histogram(name: str, data: List[int], max_height=None):
    output = []
    if not data:
        output.append(f"No data provided for {name}")
        return

    max_value = max(data)

    if max_height is None:
        max_height = max_value

    scaled_data = [math.ceil((value / max_value) * max_height) for value in data]
    for row in range(max_height, 0, -1):
        line = ""
        for value in scaled_data:
            if value >= row:
                line += "█"
            else:
                line += " "
        line = "|" + line
        output.append(line)

    output.append(f"+{'-' * (len(data))}")
    output.append(f"0{' ' * (len(data)-1)}{len(data)}")
    output.append(f"^-Histogram of {name}")

    print("\n".join(output))


def generate_histogram_from_pcap(
    pcap_path: str,
    buckets: int,
    allow_packet_filter: Optional[Callable[[Packet], bool]],
) -> typing.List[int]:
    print("Looking for a pcap at", pcap_path)

    first_packet_time = None
    timestamps = []

    with PcapReader(pcap_path) as pcap_reader:
        first_packet = True
        for pkt in pcap_reader:
            if first_packet:
                first_packet_time = pkt.time
                first_packet = False

            if allow_packet_filter and not allow_packet_filter(pkt):
                continue

            timestamps.append(pkt.time - first_packet_time)

    # we either filtered out everything or didn't receive any traffic
    if len(timestamps) == 0:
        return []

    return _generate_histogram(timestamps, buckets)


@pytest.mark.asyncio
async def test_histogram():
    data = []
    for _ in range(10):
        data.append(2)
        data.append(3)

    for _ in range(50):
        data.append(4)

    data.append(9)

    assert _generate_histogram(data, 10, 1) == [0, 0, 10, 10, 50, 0, 0, 0, 0, 1]
