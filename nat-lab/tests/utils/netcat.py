import asyncio
import platform
from utils.connection import Connection
from utils.process import Process
from utils.output_notifier import OutputNotifier
from datetime import datetime
from typing import Optional, List, Dict, AsyncIterator
from contextlib import asynccontextmanager


class NetCat:
    def __init__(
        self,
        connection: Connection,
        port: int,
        host: Optional[str] = None,
        listen: bool = False, # lflag
        udp: bool = False, # uflag
        detached: bool = False, # dflag
        port_scan: bool = False, # zflag
    ):
        flags = "-nv"
        if listen:
            flags += "l"
        if udp:
            flags += "u"
        if detached:
            flags += "d"
        if port_scan:
            flags += "z"

        command = ["nc", flags, str(port)]
        if host:
            command.insert(-1, host)

        self._process: Process = connection.create_process(command)
        self._connection: Connection = connection
        self._stdout_data: str = ""
        self._output_notifier: OutputNotifier = OutputNotifier()
        self._data_received: asyncio.Event = asyncio.Event()

    async def receive_data(self) -> str:
        await self.data_received()
        data = self._stdout_data
        self._stdout_data = ""
        return data

    async def send_data(self, data: str) -> None:
        await self._process.escape_and_write_stdin([data])
        return None

    async def on_stdout(self, stdout: str) -> None:
        self._stdout_data += stdout
        self._data_received.set()

        return None

    async def on_stderr(self, stderr: str) -> None:
        print(datetime.now(), "NetCat stderr:", stderr)
        await self._output_notifier.handle_output(stderr)
        return None

    async def data_received(self) -> None:
        await self._data_received.wait()
        self._data_received.clear()

    async def execute(self) -> None:
        await self._process.execute(stdout_callback=self.on_stdout, stderr_callback=self.on_stderr)

    @asynccontextmanager
    async def run(self) -> AsyncIterator["NetCat"]:
        async with self._process.run(stdout_callback=self.on_stdout, stderr_callback=self.on_stderr):
            await self._process.wait_stdin_ready()
            yield self

class NetCatServer(NetCat):
    def __init__(
        self,
        connection: Connection,
        port: int,
        udp: bool = False,
    ):
        super().__init__(connection, port, listen=True, udp=udp)
        self._listening_event: asyncio.Event = asyncio.Event()
        self._output_notifier.notify_output("Listening on", self._listening_event)
        self._connection_event: asyncio.Event = asyncio.Event()
        self._output_notifier.notify_output("Connection received on", self._connection_event)

    @asynccontextmanager
    async def run(self) -> AsyncIterator["NetCatServer"]:
        async with self._process.run(stdout_callback=self.on_stdout, stderr_callback=self.on_stderr):
            await self._process.wait_stdin_ready()
            yield self

    async def listening_started(self) -> None:
        if platform.system() == "Darwin":
            return None

        await self._listening_event.wait()
        self._listening_event.clear()

    async def connection_received(self) -> None:
        if platform.system() == "Darwin":
            return None

        await self._connection_event.wait()
        self._connection_event.clear()

class NetCatClient(NetCat):
    def __init__(
        self,
        connection: Connection,
        port: int,
        host: str,
        udp: bool = False, # uflag
        detached: bool = False, # dflag
        port_scan: bool = False, # zflag
    ):
        super().__init__(connection, port, host, listen=False, udp=udp, detached=detached, port_scan=port_scan)
        self._connection_event: asyncio.Event = asyncio.Event()
        self._output_notifier.notify_output("Connection to", self._connection_event)

    @asynccontextmanager
    async def run(self) -> AsyncIterator["NetCatClient"]:
        async with self._process.run(stdout_callback=self.on_stdout, stderr_callback=self.on_stderr):
            await self._process.wait_stdin_ready()
            yield self

    async def connection_succeeded(self) -> None:
        await self._connection_event.wait()
        self._connection_event.clear()
