import pytest
from scapy.layers.inet import TCP, ICMP  # type: ignore
from tests.utils import generate_histogram, generate_packet_delay_histogram
from tests.utils.testing import log_test_passed


@pytest.mark.utils
async def test_histogram():
    data = []
    for _ in range(10):
        data.append(2)
        data.append(3)

    for _ in range(50):
        data.append(4)

    data.append(9)

    assert generate_histogram(data, 10, 1) == [0, 0, 10, 10, 50, 0, 0, 0, 0, 1]
    log_test_passed()


@pytest.mark.utils
@pytest.mark.parametrize(
    "filter_name,filter_func,expected_hs",
    [
        (
            "icmp",
            lambda p: p.haslayer(ICMP),
            # fmt: off
            [8, 0, 0, 0, 0, 0, 0, 7, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            # fmt: on
        ),
        (
            "tcp",
            lambda p: p.haslayer(TCP),
            # fmt: off
            [ 41, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,0,],
            # fmt: on
        ),
    ],
)
def test_stats_and_filters_delay(filter_name, filter_func, expected_hs):
    # Test packet capture file made inside of a docker container that has some TCP, UDP, ARP, ICMP packets, few ARP packets and ping every 7seconds
    # It is very small pcap which can be easily observed and assertions made. It is very small, in total of 66 packets
    pcap_path = "./tests/utils/test.pcap"

    delay_hs = generate_packet_delay_histogram(
        pcap_path, 30, [(filter_name, filter_func)]
    )
    assert expected_hs == delay_hs
    log_test_passed()
