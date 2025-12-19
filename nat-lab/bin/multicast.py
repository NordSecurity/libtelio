import argparse
import socket
import sys

SSDP_IP: str = "239.255.255.250"
SSDP_PORT: int = 1900
SSDP_REQ: bytes = b"SSDP_REQUEST"
SSDP_RESP: bytes = b"SSDP_RESPONSE"
MDNS_IP: str = "224.0.0.251"
MDNS_PORT: int = 5353
MDNS_REQ: bytes = b"MDNS_REQUEST"
MDNS_RESP: bytes = b"MDNS_RESPONSE"


def ssdp_client(timeout: int | None):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    s.bind(("0.0.0.0", 0))
    s.sendto(SSDP_REQ, (SSDP_IP, SSDP_PORT))
    buf = s.recv(2048)
    assert buf == SSDP_RESP


def ssdp_server(timeout: int | None):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    if sys.platform == "darwin":
        # On macOS SO_REUSEPORT allows completely duplicate bindings by multiple processes
        # if they all set SO_REUSEPORT before
        # This option permits multiple instances of a program to each receive UDP/IP multicast or
        # broadcast datagrams destined for the bound port
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
    else:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("0.0.0.0", SSDP_PORT))

    mreq = socket.inet_aton(SSDP_IP) + socket.inet_aton("0.0.0.0")
    s.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)

    print("Listening", flush=True)
    while True:
        (buf, peer_addr) = s.recvfrom(2048)
        if buf == SSDP_REQ:
            s.sendto(SSDP_RESP, peer_addr)
            break


def mdns_client(timeout: int | None):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    if sys.platform == "darwin":
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
    else:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("0.0.0.0", MDNS_PORT))

    mreq = socket.inet_aton(MDNS_IP) + socket.inet_aton("0.0.0.0")
    s.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)

    s.sendto(MDNS_REQ, (MDNS_IP, MDNS_PORT))
    while True:
        buf = s.recv(2048)
        if buf == MDNS_RESP:
            break


def mdns_server(timeout: int | None):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    if sys.platform == "darwin":
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
    else:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("0.0.0.0", MDNS_PORT))

    mreq = socket.inet_aton(MDNS_IP) + socket.inet_aton("0.0.0.0")
    s.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)

    print("Listening", flush=True)
    while True:
        buf = s.recv(2048)
        if buf == MDNS_REQ:
            s.sendto(MDNS_RESP, (MDNS_IP, MDNS_PORT))
            break


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
        "-t", "--timeout", type=int, help="timeout for socket operations"
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
