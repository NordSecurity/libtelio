from utils.asyncio_util import run_async, cancel_future
from utils.connection import Connection, TargetOS
from utils.process import Process
from typing import Coroutine, Optional
import asyncio

# This utility uses the standard OS provided `ping` binaries.
# It should work for Linux, Windows and Mac.


class Ping:
    _ip: str
    _process: Process
    _stop: Optional[Coroutine]
    _next_ping_event: asyncio.Event
    _connection: Connection

    def __init__(self, connection: Connection, ip: str) -> None:
        self._ip = ip
        self._connection = connection
        if connection.target_os == TargetOS.Windows:
            self._process = connection.create_process(["ping", "-t", ip])
        else:
            self._process = connection.create_process(["ping", ip])
        self._stop = None
        self._next_ping_event = asyncio.Event()

    def execute(self) -> "Ping":
        command_coroutine = run_async(
            self._process.execute(stdout_callback=self._on_stdout)
        )

        async def stop(self) -> None:
            await cancel_future(command_coroutine)
            if self._connection.target_os == TargetOS.Windows:
                await self._connection.create_process(
                    ["taskkill", "/IM", "ping.exe", "/F"]
                ).execute()
            else:
                await self._connection.create_process(["killall", "ping"]).execute()

        self._stop = stop(self)

        return self

    async def _on_stdout(self, stdout: str) -> None:
        for line in stdout.splitlines():
            if line.find("from {}".format(self._ip)) > 0:
                self._next_ping_event.set()

    async def wait_for_next_ping(self) -> None:
        self._next_ping_event.clear()
        await self._next_ping_event.wait()
        self._next_ping_event.clear()

    async def stop(self) -> None:
        if self._stop:
            await self._stop

    async def __aenter__(self) -> "Ping":
        return self.execute()

    async def __aexit__(self, exc_type, exc, tb):
        await self.stop()
