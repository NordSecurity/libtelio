from utils.connection import Connection
from utils.process import Process
from utils.asyncio_util import run_async, cancel_future
from typing import Optional, Coroutine
from utils import OutputNotifier, connection_util
import asyncio
import telio


async def check_derp_connection(
    client: telio.Client, server_ip: str, state: bool
) -> Optional[telio.DerpServer]:
    while True:
        server = await client.get_derp_server()

        if isinstance(server, telio.DerpServer):
            if state:
                if server.ipv4 == server_ip and server.conn_state == "connected":
                    return server
            else:
                if server.ipv4 != server_ip:
                    return server
        await asyncio.sleep(1)


class DerpTarget:
    _stop: Optional[Coroutine]
    _process: Process
    _output_notifier: OutputNotifier

    def __init__(self, connection: Connection, server: str) -> None:
        self._stop = None
        self._process = connection.create_process(
            [
                connection_util.get_libtelio_binary_path("derpcli", connection),
                "-t",
                "-s",
                server,
                "-vv",
            ]
        )
        self._output_notifier = OutputNotifier()

    async def run(self) -> "DerpTarget":
        async def on_stdout(stdout: str) -> None:
            self._output_notifier.handle_output(stdout)

        process_future = run_async(self._process.execute(stdout_callback=on_stdout))

        async def stop() -> None:
            await cancel_future(process_future)

        self._stop = stop()

        return self

    async def wait_message_received(self, message: str) -> None:
        event = asyncio.Event()
        self._output_notifier.notify_output(message, event)
        await event.wait()

    async def stop(self) -> None:
        if self._stop:
            await self._stop

    async def __aenter__(self) -> "DerpTarget":
        return await self.run()

    async def __aexit__(self, exc_type, exc, tb):
        await self.stop()


class DerpClient:
    _stop: Optional[Coroutine]
    _process: Process

    def __init__(self, connection: Connection, server: str, data: str) -> None:
        self._stop = None
        self._process = connection.create_process(
            [
                connection_util.get_libtelio_binary_path("derpcli", connection),
                "-s",
                server,
                "-vv",
                "-a",
                data,
            ]
        )

    async def run(self) -> "DerpClient":
        process_future = run_async(self._process.execute())

        async def stop() -> None:
            await cancel_future(process_future)

        self._stop = stop()

        return self

    async def stop(self) -> None:
        if self._stop:
            await self._stop

    async def __aenter__(self) -> "DerpClient":
        return await self.run()

    async def __aexit__(self, exc_type, exc, tb):
        await self.stop()
