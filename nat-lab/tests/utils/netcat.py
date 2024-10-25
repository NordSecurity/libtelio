import asyncio
from config import LIBTELIO_BINARY_PATH_MAC_VM, LIBTELIO_BINARY_PATH_WINDOWS_VM
from contextlib import asynccontextmanager
from datetime import datetime
from typing import Optional, AsyncIterator
from utils.connection import Connection, TargetOS
from utils.output_notifier import OutputNotifier
from utils.process import Process
from utils.python import get_python_binary


def _get_netcat_script_path(connection: Connection) -> str:
    if connection.target_os == TargetOS.Windows:
        return LIBTELIO_BINARY_PATH_WINDOWS_VM + "netcat.py"
    if connection.target_os == TargetOS.Mac:
        return LIBTELIO_BINARY_PATH_MAC_VM + "netcat.py"
    return "nc"


class NetCat:
    """Wrapper class for the NC command"""

    def __init__(
        self,
        connection: Connection,
        host_ip: Optional[str],
        port: int,
        listen: bool = False,  # l-flag
        udp: bool = False,  # u-flag
        ipv6: bool = False,  # 6-flag
        detached: bool = False,  # d-flag
        port_scan: bool = False,  # z-flag
        source_ip: Optional[str] = None,  # s-flag
    ):
        """
        Create an instance of the nc command

        Parameters
        ----------
            connection : Connection
                Target connection to run the command on
            port : int
                Port number to connect to
            host_ip : str | None
                IP address of the host to connect to, not necessery when the listen option is used
            listen : bool
                Listen for an incoming connection rather than initiate a connection to a remote host
            udp : bool
                Use UDP instead of TCP protocol
            ipv6 : bool
                Force to use ipv6 addresses only
            detached : bool
                Do not attempt to read from stdin
            port_scan : bool
                Scan for listening daemons, without sending any data
            source_ip : str | None
                Specifies the IP of the interface which is used to send the packets
        """
        flags = "-nv"  # don't do any dns lookups and enable vebose output
        flags += "6" if ipv6 else "4"
        if listen:
            flags += "l"
        if udp:
            flags += "u"
        if detached:
            flags += "d"
        if port_scan and not listen:
            flags += "z"

        # use the built in netcat command on linux
        if connection.target_os == TargetOS.Linux:
            command = ["nc", flags, str(port)]
        else:
            command = [
                get_python_binary(connection),
                _get_netcat_script_path(connection),
                flags,
                str(port),
            ]

        if source_ip and not listen:
            command.insert(-1, "-s")
            command.insert(-1, source_ip)
        if host_ip:
            command.insert(-1, host_ip)

        self._process: Process = connection.create_process(command)
        self._connection: Connection = connection
        self._stdout_data: str = ""
        self._output_notifier: OutputNotifier = OutputNotifier()
        self._data_received: asyncio.Event = asyncio.Event()

    async def receive_data(self) -> str:
        """Receive data from stdout"""
        await self._data_received.wait()
        self._data_received.clear()
        data = self._stdout_data
        self._stdout_data = ""
        return data

    async def send_data(self, data: str) -> None:
        """Write data to stdin"""
        await self._process.escape_and_write_stdin([data])
        return None

    async def on_stdout(self, stdout: str) -> None:
        """Handle incoming data"""
        self._stdout_data += stdout
        self._data_received.set()
        return None

    async def on_stderr(self, stderr: str) -> None:
        """Handle verbose status messages"""
        print(datetime.now(), "netcat:", stderr.strip())
        await self._output_notifier.handle_output(stderr.strip())
        return None

    async def execute(self) -> None:
        await self._process.execute(
            stdout_callback=self.on_stdout, stderr_callback=self.on_stderr
        )

    async def is_done(self) -> None:
        await self._process.is_done()

    @asynccontextmanager
    async def run(self) -> AsyncIterator["NetCat"]:
        async with self._process.run(
            stdout_callback=self.on_stdout, stderr_callback=self.on_stderr
        ):
            await self._process.wait_stdin_ready()
            yield self


class NetCatServer(NetCat):
    """Helper class for NC server"""

    def __init__(
        self,
        connection: Connection,
        port: int,
        udp: bool = False,
        ipv6: bool = False,
    ):
        super().__init__(connection, None, port, listen=True, udp=udp, ipv6=ipv6)
        self._listening_event: asyncio.Event = asyncio.Event()
        status = "Listening" if not udp else "Bound"
        address = "::" if ipv6 else "0.0.0.0"
        self._output_notifier.notify_output(
            f"{status} on {address} {str(port)}", self._listening_event
        )
        self._connection_event: asyncio.Event = asyncio.Event()
        self._output_notifier.notify_output(
            "Connection received", self._connection_event
        )

    @asynccontextmanager
    async def run(self) -> AsyncIterator["NetCatServer"]:
        async with self._process.run(
            stdout_callback=self.on_stdout, stderr_callback=self.on_stderr
        ):
            await self._process.wait_stdin_ready()
            yield self

    async def listening_started(self) -> None:
        """Wait for listening started event"""
        await self._listening_event.wait()
        self._listening_event.clear()

    async def connection_received(self) -> None:
        """Wait for connection received event"""
        await self._connection_event.wait()
        self._connection_event.clear()


class NetCatClient(NetCat):
    """Helper class for NC client"""

    def __init__(
        self,
        connection: Connection,
        host: str,
        port: int,
        udp: bool = False,
        ipv6: bool = False,
        detached: bool = False,
        port_scan: bool = False,
        source_ip: Optional[str] = None,
    ):
        super().__init__(
            connection,
            host,
            port,
            listen=False,
            udp=udp,
            ipv6=ipv6,
            detached=detached,
            port_scan=port_scan,
            source_ip=source_ip,
        )
        self._connection_event: asyncio.Event = asyncio.Event()
        protocol = "tcp" if not udp else "udp"
        self._output_notifier.notify_output(
            f"{port} port [{protocol}/*] succeeded",
            self._connection_event,
        )

    @asynccontextmanager
    async def run(self) -> AsyncIterator["NetCatClient"]:
        async with self._process.run(
            stdout_callback=self.on_stdout, stderr_callback=self.on_stderr
        ):
            await self._process.wait_stdin_ready()
            yield self

    async def connection_succeeded(self) -> None:
        """Wait for connection succeeded event"""
        await self._connection_event.wait()
        self._connection_event.clear()
