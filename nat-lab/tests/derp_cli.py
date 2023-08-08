import asyncio
from contextlib import asynccontextmanager
from typing import AsyncIterator
from utils.connection import Connection
from utils.connection_util import get_libtelio_binary_path
from utils.output_notifier import OutputNotifier
from utils.process import Process


class DerpTarget:
    _process: Process
    _output_notifier: OutputNotifier

    def __init__(self, connection: Connection, server: str) -> None:
        self._stop = None
        self._process = connection.create_process(
            [get_libtelio_binary_path("derpcli", connection), "-t", "-s", server, "-vv"]
        )
        self._output_notifier = OutputNotifier()

    async def on_stdout(self, stdout: str) -> None:
        self._output_notifier.handle_output(stdout)

    async def execute(self) -> None:
        await self._process.execute(stdout_callback=self.on_stdout)

    async def wait_message_received(self, message: str) -> None:
        event = asyncio.Event()
        self._output_notifier.notify_output(message, event)
        await event.wait()

    @asynccontextmanager
    async def run(self) -> AsyncIterator["DerpTarget"]:
        async with self._process.run(stdout_callback=self.on_stdout):
            yield self


class DerpClient:
    _process: Process

    def __init__(self, connection: Connection, server: str, data: str) -> None:
        self._process = connection.create_process(
            [
                get_libtelio_binary_path("derpcli", connection),
                "-s",
                server,
                "-vv",
                "-a",
                data,
            ]
        )

    async def execute(self) -> None:
        await self._process.execute()

    @asynccontextmanager
    async def run(self) -> AsyncIterator["DerpClient"]:
        async with self._process.run():
            yield self
