import argparse
import errno
import selectors
import socket
import sys
import time

UDP_SCAN_COUNT: int = 3
RECV_SIZE = 4096


class NetCat:
    """A netcat clone written in Python"""

    def __init__(self, args):
        self.args: argparse.Namespace = args
        self.verbose: bool = args.v
        self.udp: bool = self.args.u
        self.sock_type: str = "udp" if self.udp else "tcp"
        self.listen: bool = self.args.l
        self.ipv6: bool = self.args.ipv6
        self.sock: socket.socket = self._create_socket()
        self.client_addr: str | None = None
        self.selector: selectors.DefaultSelector = selectors.DefaultSelector()
        self.should_close: bool = False

    def _vprint(self, *args, **kwargs):
        """print an event to stderr in verbose mode"""
        if self.verbose:
            print(*args, **kwargs, file=sys.stderr)

    def _create_socket(self) -> socket.socket:
        """Helper to create socket"""
        family = socket.AF_INET6 if self.ipv6 else socket.AF_INET
        sock_type = socket.SOCK_DGRAM if self.udp else socket.SOCK_STREAM
        try:
            s = socket.socket(family, sock_type)
            return s
        except OSError as e:
            print(f"error creating socket: {e}", file=sys.stderr)
            sys.exit(1)

    def _connect(self):
        """Connect to a remote listener"""
        hostname = self.args.hostname
        port = self.args.port

        try:
            # Bind to a local port or source address if specified
            if self.args.p or self.args.s:
                local_address: str = self.args.s if self.args.s else ""
                local_port: int = self.args.p if self.args.p else 0

                self.sock.bind((local_address, local_port))

            self.sock.connect((hostname, port))
            if self.udp and self.verbose:
                self._udptest()
            self._vprint(
                f"Connection to {hostname} {port} port [{self.sock_type}/*] succeeded!"
            )
        except OSError as e:
            print(
                f"nc: connect to {hostname} port {port} ({self.sock_type}) failed: {e.strerror}",
                file=sys.stderr,
            )
            if e.errno == errno.EBADF:
                # connection closed
                sys.exit(0)
            sys.exit(1)

    def _listen(self):
        """Listen for incoming connections"""
        # Set SO_REUSEPORT option
        try:
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        except AttributeError:
            # SO_REUSEPORT may not be available on all systems, fall back to SO_REUSEADDR
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        port = self.args.port
        hostname = self.args.hostname
        bind_addr = hostname if hostname else "::" if self.ipv6 else "0.0.0.0"
        self.sock.bind((bind_addr, port))

        if self.udp:
            self._vprint(f"Bound on {bind_addr} {port}")
        else:
            self.sock.listen(1)
            self._vprint(f"Listening on {bind_addr} {port}")
            conn, addr = self.sock.accept()
            self._vprint(f"Connection received on {addr[0]} {addr[1]}")
            self.sock = conn

    def _udptest(self):
        """Test UDP connection"""
        # Try sending data to the socket
        for _ in range(UDP_SCAN_COUNT):
            self.sock.send(b"X")
            time.sleep(0.5)

    def _register_socket(self):
        """Register the socket to the selector for read events"""
        self.selector.register(self.sock, selectors.EVENT_READ, self._read_from_socket)

    def _register_stdin(self):
        """Register stdin to the selector for read events, unless disabled"""
        if not self.args.d:
            self.selector.register(
                sys.stdin, selectors.EVENT_READ, self._read_from_stdin
            )

    def _read_from_socket(self):
        """Handle incoming data from the socket"""
        data, addr = self.sock.recvfrom(RECV_SIZE)
        if self.udp and self.listen and not self.client_addr:
            self._vprint(f"Connection received on {addr[0]} {addr[1]}")
            self.client_addr = addr
        if data:
            sys.stdout.buffer.write(data)
            sys.stdout.flush()
        else:
            # Connection closed
            self.selector.unregister(self.sock)
            self.should_close = True

    def _read_from_stdin(self):
        """Handle input from stdin and send it over the socket"""
        data = sys.stdin.buffer.readline()
        if data:
            if self.listen and self.client_addr:
                self.sock.sendto(data, self.client_addr)
            else:
                self.sock.send(data)
        else:
            # EOF on stdin
            self.selector.unregister(sys.stdin)
            self.should_close = True

    def run(self):
        try:
            if self.args.l:
                self._listen()
            else:
                self._connect()
            if not self.args.z:
                self._register_socket()
                self._register_stdin()
                while not self.should_close:
                    events = self.selector.select(timeout=None)
                    for key, _ in events:
                        callback = key.data
                        callback()
        except KeyboardInterrupt:
            print("Keyboard Interrupt")
            sys.exit(2)
        except OSError as e:
            print(f"nc: {e}", file=sys.stderr)
            if e.errno in (errno.EBADF, errno.ECONNREFUSED):
                sys.exit(0)
            sys.exit(1)
        finally:
            self.selector.close()
            if self.sock:
                self.sock.close()


def main():
    parser = argparse.ArgumentParser(description="Netcat clone in Python")
    parser.add_argument("-6", dest="ipv6", action="store_true", help="Use IPv6")
    parser.add_argument(
        "-4", dest="ipv4", action="store_true", help="Use IPv4 addresses"
    )
    parser.add_argument("-v", action="store_true", help="Verbose mode")
    parser.add_argument("-n", action="store_true", help="Do not resolve hostnames")
    parser.add_argument("-l", action="store_true", help="Listen mode (server)")
    parser.add_argument("-u", action="store_true", help="UDP mode")
    parser.add_argument("-d", action="store_true", help="Do not read from stdin")
    parser.add_argument(
        "-z", action="store_true", help="Zero-I/O mode [used for scanning]"
    )
    parser.add_argument("-p", type=int, help="Bind to local port number")
    parser.add_argument("-s", type=str, help="Bind to local source address")
    parser.add_argument("hostname", nargs="?", help="Hostname or IP address")
    parser.add_argument("port", type=int, help="Port number")
    args = parser.parse_args()

    if args.z and args.l:
        parser.error("Cannot use -z in listen mode (-l)")
    if args.s and args.l:
        parser.error("Cannot use -s in listen mode (-l)")
    if args.p and args.l:
        parser.error("Cannot use -p in listen mode (-l)")

    if not args.port:
        parser.error("Port required")

    if not args.l:
        # Connect mode
        if not args.hostname:
            parser.error("Hostname required")

    netcat = NetCat(args)
    netcat.run()


if __name__ == "__main__":
    main()
