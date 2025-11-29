import asyncio
import math
import os
import subprocess
import tempfile
import typing
from scapy.all import PcapReader  # type: ignore
from tests.utils.logger import log
from typing import List, Any


def generate_histogram(data: list, buckets: int, bucket_size: int = 1) -> List[int]:
    """Generate histogram based on passed data. Each item increases the count in respective bucket of histogram"""
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
    """Capture traffic on the target container for a duration of time. Returned is the path of a *.pcap file"""

    cmd_rm = f"docker exec --privileged {container_name} rm /home/capture.pcap"
    os.system(cmd_rm)

    iface = "any"
    capture_path = "/home/capture.pcap"

    cmd = f"docker exec -d --privileged {container_name} tcpdump -i {iface} -U -w {capture_path}"
    res = os.system(cmd)
    if res != 0:
        raise RuntimeError(f"Failed to launch tcpdump on {container_name}")

    await asyncio.sleep(duration_s)

    # Use temporary file so it would not collide, however don't delete it as it
    # leaves ability for us to inspect it manually
    with tempfile.NamedTemporaryFile(delete=False) as tmpfile:
        local_path = tmpfile.name
        log.info("Copying pcap to %s", local_path)
        subprocess.run([
            "docker",
            "cp",
            container_name + ":" + "/home/capture.pcap",
            local_path,
        ])

        cmd_rm = f"docker exec --privileged {container_name} pkill tcpdump"
        os.system(cmd_rm)

        return local_path


# Render ASCII chart into a string
def render_chart(data: List[int], max_height=10) -> str:
    """Render ASCII chart into a string and return it"""

    if not data:
        raise ValueError("No data provided to render")

    output = []

    max_value = max(data)
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

    return "\n".join(output)


def generate_packet_delay_histogram(
    pcap_path: str,
    buckets: int,
    allow_packet_filters: Any,
) -> typing.List[int]:
    """Generate histogram based on the relative packet(and packet before) timestamp differences. Good for observing bursts"""

    log.debug("Looking for a pcap at %s", pcap_path)

    last_packet_time = None
    timestamps = []

    with PcapReader(pcap_path) as pcap_reader:
        for pkt in pcap_reader:
            pkttime = pkt.time  # type: ignore
            if last_packet_time is None:
                last_packet_time = pkttime

            if all(f[1](pkt) for f in allow_packet_filters):
                timestamps.append(pkttime - last_packet_time)
                last_packet_time = pkttime

    if len(timestamps) == 0:
        raise ValueError(
            "No data for histogram generation. It was either fully filtered out or not present"
        )

    return generate_histogram(timestamps, buckets)


def get_ordered_histogram_score(data: typing.List[int]) -> int:
    # Assumes the histogram order matters and each item going to the right adds more to the score
    # Useful to quantity a score for things like periods between packets
    score = 0
    for i, value in enumerate(data, start=1):
        score += i * value
    return score


def generate_packet_distribution_histogram(
    pcap_path: str,
    buckets: int,
    allow_packet_filters: Any,
) -> typing.List[int]:
    """Generate histogram based on absolute packet timestamps. Good for observing trends and patterns"""

    log.debug("Looking for a pcap at %s", pcap_path)

    first_packet_time = None
    timestamps = []

    with PcapReader(pcap_path) as pcap_reader:
        for pkt in pcap_reader:
            pkttime = pkt.time  # type: ignore
            if first_packet_time is None:
                first_packet_time = pkttime

            if all(f[1](pkt) for f in allow_packet_filters):
                timestamps.append(pkttime - first_packet_time)

    if len(timestamps) == 0:
        raise ValueError(
            "No data for histogram generation. It was either fully filtered out or not present"
        )

    return generate_histogram(timestamps, buckets)
