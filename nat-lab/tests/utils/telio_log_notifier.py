import asyncio
from contextlib import asynccontextmanager
from tests.utils.connection import Connection, TargetOS
from tests.utils.output_notifier import OutputNotifier
from tests.utils.process import Process
from typing import AsyncIterator


class TelioLogNotifier:
    _process: Process
    _next_ping_event: asyncio.Event
    _connection: Connection

    def __init__(self, connection: Connection) -> None:
        assert (
            connection.target_os == TargetOS.Linux
        ), "TelioLogNotifier supported only on Linux"
        self._connection = connection
        self._process = connection.create_process(
            ["tail", "-n", "1", "-F", "/tcli.log"], quiet=True
        )
        self._output_notifier = OutputNotifier()

    def notify_output(self, what: str) -> asyncio.Event:
        event = asyncio.Event()
        self._output_notifier.notify_output(what, event)
        return event

    @asynccontextmanager
    async def run(self) -> AsyncIterator["TelioLogNotifier"]:
        async with self._process.run(
            stdout_callback=self._output_notifier.handle_output
        ):
            await self._process.wait_stdin_ready()
            yield self
