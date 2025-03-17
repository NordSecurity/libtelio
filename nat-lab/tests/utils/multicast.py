import asyncio
from asyncio import Event
from config import LIBTELIO_BINARY_PATH_VM_MAC, LIBTELIO_BINARY_PATH_WINDOWS_VM
from contextlib import asynccontextmanager
from datetime import datetime
from typing import AsyncIterator
from utils.connection import Connection, TargetOS
from utils.process import Process
from utils.python import get_python_binary


def _get_multicast_script_path(connection: Connection) -> str:
    if connection.target_os == TargetOS.Linux:
        return "/libtelio/nat-lab/bin/multicast.py"
    if connection.target_os == TargetOS.Windows:
        return LIBTELIO_BINARY_PATH_WINDOWS_VM + "multicast.py"
    return LIBTELIO_BINARY_PATH_VM_MAC + "multicast.py"


class MulticastClient:
    _process: Process
    _connection: Connection

    def __init__(self, connection: Connection, protocol: str) -> None:
        self._connection = connection
        self._process = connection.create_process([
            get_python_binary(connection),
            _get_multicast_script_path(connection),
            f"--{protocol}",
            "-c",
            "-t",
            "5",
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
            get_python_binary(connection),
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
        await asyncio.wait_for(self._server_ready_event.wait(), timeout=10.0)
        print(datetime.now(), "MulticastServer is ready")

    @asynccontextmanager
    async def run(self) -> AsyncIterator["MulticastServer"]:
        print(datetime.now(), "MulticastServer starting")
        async with self._process.run(stdout_callback=self.on_stdout):
            await asyncio.sleep(0.1)
            yield self
