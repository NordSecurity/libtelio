import argparse
import socket

SSDP_IP: str = "239.255.255.250"
SSDP_PORT: int = 1900
MDNS_IP: str = "224.0.0.251"
MDNS_PORT: int = 5353


def ssdp_client(timeout: int):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    s.bind(("0.0.0.0", 0))
    s.sendto(b"SSDP_REQUEST", (SSDP_IP, SSDP_PORT))
    (buf, peer_addr) = s.recvfrom(2048)
    print(f"Received data: {buf.decode()} from: {peer_addr}")


def ssdp_server(timeout: int):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    s.bind(("0.0.0.0", SSDP_PORT))

    mreq = socket.inet_aton(SSDP_IP) + socket.inet_aton("0.0.0.0")
    s.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)

    print("Listening", flush=True)
    (buf, peer_addr) = s.recvfrom(2048)
    print(f"Received data: {buf.decode()} from: {peer_addr}", flush=True)
    s.sendto(b"SSDP_RESPONSE", peer_addr)


def mdns_client(timeout: int):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    s.bind(("0.0.0.0", MDNS_PORT))

    mreq = socket.inet_aton(MDNS_IP) + socket.inet_aton("0.0.0.0")
    s.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)

    s.sendto(b"MDNS_REQUEST", (MDNS_IP, MDNS_PORT))
    (buf, peer_addr) = s.recvfrom(2048)
    print(f"Received data: {buf.decode()} from: {peer_addr}")


def mdns_server(timeout: int):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    s.bind(("0.0.0.0", MDNS_PORT))

    mreq = socket.inet_aton(MDNS_IP) + socket.inet_aton("0.0.0.0")
    s.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)

    print("Listening", flush=True)
    (buf, peer_addr) = s.recvfrom(2048)
    print(f"Received data: {buf.decode()} from: {peer_addr}")
    s.sendto(b"MDNS_RESPONSE", (MDNS_IP, MDNS_PORT))


def main():
    parser = argparse.ArgumentParser()
    protocol_group = parser.add_mutually_exclusive_group(required=True)
    protocol_group.add_argument(
        "-m",
        "--mdns",
        action="store_true",
        help="use mdns-like protocol (multicast request, multicast response)",
    )
    protocol_group.add_argument(
        "-u",
        "--ssdp",
        action="store_true",
        help="use ssdp-like protocol (multicast request, unicast response)",
    )
    side_group = parser.add_mutually_exclusive_group(required=True)
    side_group.add_argument("-c", "--client", action="store_true", help="act as client")
    side_group.add_argument("-s", "--server", action="store_true", help="act as server")

    parser.add_argument(
        "-t", "--timeout", type=int, required=True, help="timeout for socket operations"
    )

    args = parser.parse_args()

    if args.client:
        if args.ssdp:
            ssdp_client(args.timeout)
        else:
            mdns_client(args.timeout)
    elif args.server:
        if args.ssdp:
            ssdp_server(args.timeout)
        else:
            mdns_server(args.timeout)


if __name__ == "__main__":
    main()
