from utils.connection_tracker import parse_input, FiveTuple


def test_connection_tracker_parse_input():
    new_udp = parse_input(
        "[NEW] udp      17 30 src=127.0.0.1 dst=127.0.0.53 sport=34348 dport=53 [UNREPLIED] src=127.0.0.53 dst=127.0.0.1 sport=53 dport=34348"
    )
    assert new_udp == FiveTuple(
        protocol="udp",
        src_ip="127.0.0.1",
        src_port=34348,
        dst_ip="127.0.0.53",
        dst_port=53,
    )

    updated_udp = parse_input(
        "[UPDATE] udp      17 30 src=10.6.6.104 dst=8.8.8.8 sport=49922 dport=53 src=8.8.8.8 dst=10.6.6.104 sport=53 dport=49922"
    )
    assert updated_udp == FiveTuple(
        protocol=None,
        src_ip="10.6.6.104",
        src_port=49922,
        dst_ip="8.8.8.8",
        dst_port=53,
    )

    new_icmp_type8 = parse_input(
        "[NEW] icmp     1 30 src=10.6.6.104 dst=142.250.184.206 type=8 code=0 id=370 [UNREPLIED] src=142.250.184.206 dst=10.6.6.104 type=0 code=0 id=370"
    )
    assert new_icmp_type8 == FiveTuple(
        protocol="icmp",
        src_ip="10.6.6.104",
        src_port=None,
        dst_ip="142.250.184.206",
        dst_port=None,
    )

    updated_icmp_type8 = parse_input(
        "[UPDATE] icmp     1 30 src=10.6.6.104 dst=142.250.184.206 type=8 code=0 id=370 src=142.250.184.206 dst=10.6.6.104 type=0 code=0 id=370"
    )
    assert updated_icmp_type8 == FiveTuple(
        protocol=None,
        src_ip="10.6.6.104",
        src_port=None,
        dst_ip="142.250.184.206",
        dst_port=None,
    )

    new_icmp_type0 = parse_input(
        "[NEW] icmp     1 30 src=10.6.6.104 dst=142.250.184.206 type=0 code=0 id=370 [UNREPLIED] src=142.250.184.206 dst=10.6.6.104 type=0 code=0 id=370"
    )
    assert new_icmp_type0 == FiveTuple(
        protocol="icmp",
        src_ip="10.6.6.104",
        src_port=None,
        dst_ip="142.250.184.206",
        dst_port=None,
    )

    new_icmp_type13 = parse_input(
        "[NEW] icmp     1 30 src=127.0.0.1 dst=127.0.0.1 type=13 code=0 id=44126 [UNREPLIED] src=127.0.0.1 dst=127.0.0.1 type=14 code=0 id=44126"
    )
    assert new_icmp_type13 == FiveTuple(
        protocol=None,
        src_ip="127.0.0.1",
        src_port=None,
        dst_ip="127.0.0.1",
        dst_port=None,
    )

    new_icmpv6_type128 = parse_input(
        "[NEW] icmpv6   58 30 src=2600:1f1a:4d5e:c200:2787:af77:9c40:1365 dst=2a05:f480:2400:1e9a:5400:4ff:fe25:e8f4 type=128 code=0 id=2 [UNREPLIED] src=2a05:f480:2400:1e9a:5400:4ff:fe25:e8f4 dst=2600:1f1a:4d5e:c200:2787:af77:9c40:1365 type=666 code=0 id=2"
    )
    assert new_icmpv6_type128 == FiveTuple(
        protocol="icmpv6",
        src_ip="2600:1f1a:4d5e:c200:2787:af77:9c40:1365",
        src_port=None,
        dst_ip="2a05:f480:2400:1e9a:5400:4ff:fe25:e8f4",
        dst_port=None,
    )
    new_icmpv6_type129 = parse_input(
        "[NEW] icmpv6   58 30 src=2600:1f1a:4d5e:c200:2787:af77:9c40:1365 dst=2a05:f480:2400:1e9a:5400:4ff:fe25:e8f4 type=666 code=0 id=2 [UNREPLIED] src=2a05:f480:2400:1e9a:5400:4ff:fe25:e8f4 dst=2600:1f1a:4d5e:c200:2787:af77:9c40:1365 type=129 code=0 id=2"
    )
    assert new_icmpv6_type129 == FiveTuple(
        protocol="icmpv6",
        src_ip="2600:1f1a:4d5e:c200:2787:af77:9c40:1365",
        src_port=None,
        dst_ip="2a05:f480:2400:1e9a:5400:4ff:fe25:e8f4",
        dst_port=None,
    )
    new_icmpv6_type130 = parse_input(
        "[NEW] icmpv6   58 30 src=2600:1f1a:4d5e:c200:2787:af77:9c40:1365 dst=2a05:f480:2400:1e9a:5400:4ff:fe25:e8f4 type=130 code=0 id=2 [UNREPLIED] src=2a05:f480:2400:1e9a:5400:4ff:fe25:e8f4 dst=2600:1f1a:4d5e:c200:2787:af77:9c40:1365 type=131 code=0 id=2"
    )
    assert new_icmpv6_type130 == FiveTuple(
        protocol=None,
        src_ip="2600:1f1a:4d5e:c200:2787:af77:9c40:1365",
        src_port=None,
        dst_ip="2a05:f480:2400:1e9a:5400:4ff:fe25:e8f4",
        dst_port=None,
    )
