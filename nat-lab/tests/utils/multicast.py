from asyncio import Event
from config import LIBTELIO_BINARY_PATH_MAC_VM, LIBTELIO_BINARY_PATH_WINDOWS_VM
from contextlib import asynccontextmanager
from typing import AsyncIterator
from utils.connection import Connection, TargetOS
from utils.process import Process


def _get_python(connection: Connection) -> str:
    if connection.target_os == TargetOS.Windows:
        return "python"
    return "python3"


def _get_multicast_script_path(connection: Connection) -> str:
    if connection.target_os == TargetOS.Linux:
        return "/libtelio/nat-lab/bin/multicast.py"
    if connection.target_os == TargetOS.Windows:
        return LIBTELIO_BINARY_PATH_WINDOWS_VM + "multicast.py"
    return LIBTELIO_BINARY_PATH_MAC_VM + "multicast.py"


class MulticastClient:
    _process: Process
    _connection: Connection

    def __init__(self, connection: Connection, protocol: str) -> None:
        self._connection = connection
        self._process = connection.create_process([
            _get_python(connection),
            _get_multicast_script_path(connection),
            f"--{protocol}",
            "-c",
            "-t",
            "10",
        ])

    async def execute(self) -> None:
        await self._process.execute()


class MulticastServer:
    _process: Process
    _connection: Connection
    _server_ready_event: Event

    def __init__(self, connection: Connection, protocol: str) -> None:
        self._connection = connection
        self._server_ready_event = Event()
        self._process = connection.create_process([
            _get_python(connection),
            _get_multicast_script_path(connection),
            f"--{protocol}",
            "-s",
            "-t",
            "10",
        ])

    async def on_stdout(self, stdout: str) -> None:
        for line in stdout.splitlines():
            if line.find("Listening") >= 0:
                self._server_ready_event.set()

    async def wait_till_ready(self) -> None:
        await self._server_ready_event.wait()

    @asynccontextmanager
    async def run(self) -> AsyncIterator["MulticastServer"]:
        async with self._process.run(stdout_callback=self.on_stdout):
            yield self
