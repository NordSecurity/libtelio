import asyncio
from contextlib import asynccontextmanager
from typing import AsyncIterator
from utils.connection import Connection, TargetOS
from utils.output_notifier import OutputNotifier
from utils.process import Process


class TelioLogNotifier:
    _process: Process
    _next_ping_event: asyncio.Event
    _connection: Connection

    def __init__(self, connection: Connection) -> None:
        if connection.target_os == TargetOS.Linux:
            cmd = ["tail", "-n", "1", "-F", "/tcli.log"]
        elif connection.target_os == TargetOS.Windows:
            cmd = [
                "powershell",
                "-NoProfile",
                "-Command",
                "Get-Content -Path .\\tcli.log -Wait -Tail 1 | "
                "ForEach-Object { \"$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss.fff') $_\" }",
            ]
        else:
            # TODO: there's no reason it wouldn't work on MacOS
            raise AssertionError(
                f"Unrecognized OS for notifier: {connection.target_os}"
            )

        self._connection = connection
        self._process = connection.create_process(cmd, quiet=True)
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
