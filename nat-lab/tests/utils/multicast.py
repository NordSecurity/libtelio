import asyncio
from asyncio import Event
from contextlib import asynccontextmanager
from tests.config import LIBTELIO_BINARY_PATH_VM_MAC, LIBTELIO_BINARY_PATH_WINDOWS_VM
from tests.utils.connection import Connection, TargetOS
from tests.utils.logger import log
from tests.utils.process import Process
from tests.utils.python import get_python_binary
from typing import AsyncIterator, Optional


def _get_multicast_script_path(connection: Connection) -> str:
    if connection.target_os == TargetOS.Linux:
        return "/libtelio/nat-lab/bin/multicast.py"
    if connection.target_os == TargetOS.Windows:
        return LIBTELIO_BINARY_PATH_WINDOWS_VM + "multicast.py"
    return LIBTELIO_BINARY_PATH_VM_MAC + "multicast.py"


class MulticastClient:
    _process: Process
    _connection: Connection

    def __init__(
        self, connection: Connection, protocol: str, timeout: Optional[int], ip: str
    ) -> None:
        self._connection = connection

        cmd = [
            get_python_binary(connection),
            _get_multicast_script_path(connection),
            f"--{protocol}",
            "-c",
            "--ip",
            ip,
        ]

        if timeout is not None:
            cmd.extend(["-t", str(timeout)])

        self._process = connection.create_process(cmd)

    async def execute(self) -> None:
        await self._process.execute()


class MulticastServer:
    _process: Process
    _connection: Connection
    _server_ready_event: Event

    def __init__(
        self, connection: Connection, protocol: str, timeout: Optional[int], ip: str
    ) -> None:
        self._connection = connection
        self._server_ready_event = Event()

        cmd = [
            get_python_binary(connection),
            _get_multicast_script_path(connection),
            f"--{protocol}",
            "-s",
            "--ip",
            ip,
        ]

        if timeout is not None:
            cmd.extend(["-t", str(timeout)])

        self._process = connection.create_process(cmd)

    async def on_stdout(self, stdout: str) -> None:
        for line in stdout.splitlines():
            if line.find("Listening") >= 0:
                self._server_ready_event.set()

    async def wait_till_ready(self) -> None:
        await self._server_ready_event.wait()
        log.info("MulticastServer is ready")

    @asynccontextmanager
    async def run(self) -> AsyncIterator["MulticastServer"]:
        log.info("MulticastServer starting")
        async with self._process.run(stdout_callback=self.on_stdout):
            await asyncio.sleep(0.1)
            yield self
