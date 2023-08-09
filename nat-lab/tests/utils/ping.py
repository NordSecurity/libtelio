import asyncio
from contextlib import asynccontextmanager
from typing import AsyncIterator
from utils.connection import Connection, TargetOS
from utils.process import Process

# This utility uses the standard OS provided `ping` binaries.
# It should work for Linux, Windows and Mac.


class Ping:
    _ip: str
    _process: Process
    _next_ping_event: asyncio.Event
    _connection: Connection

    def __init__(self, connection: Connection, ip: str) -> None:
        self._ip = ip
        self._connection = connection
        if connection.target_os == TargetOS.Windows:
            self._process = connection.create_process(["ping", "-t", ip])
        else:
            self._process = connection.create_process(["ping", ip])
        self._next_ping_event = asyncio.Event()

    async def on_stdout(self, stdout: str) -> None:
        for line in stdout.splitlines():
            if line.find(f"from {self._ip}") > 0:
                self._next_ping_event.set()

    async def execute(self) -> None:
        await self._process.execute(stdout_callback=self.on_stdout)

    async def wait_for_next_ping(self) -> None:
        self._next_ping_event.clear()
        await self._next_ping_event.wait()
        self._next_ping_event.clear()

    @asynccontextmanager
    async def run(self) -> AsyncIterator["Ping"]:
        async with self._process.run(stdout_callback=self.on_stdout):
            yield self
