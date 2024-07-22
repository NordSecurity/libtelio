import asyncio
import os
from contextlib import asynccontextmanager
from typing import AsyncIterator, Optional
from utils.connection import Connection, TargetOS
from utils.connection_util import get_libtelio_binary_path
from utils.output_notifier import OutputNotifier
from utils.process import Process
from utils.testing import test_name_safe_for_file_name


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
        self._process = connection.create_process([
            get_libtelio_binary_path("derpcli", connection),
            "-s",
            server,
            "-vv",
            "-a",
            data,
        ])

    async def execute(self) -> None:
        await self._process.execute()

    @asynccontextmanager
    async def run(self) -> AsyncIterator["DerpClient"]:
        async with self._process.run():
            yield self


# Log name here is useful when when we need logs from multiple instances of derpcli running on the same test
async def save_derpcli_logs(
    connection: Connection, log_name: Optional[str] = None
) -> None:
    if os.environ.get("NATLAB_SAVE_LOGS") is None:
        return

    if log_name is None:
        log_name = ""
    else:
        log_name = "_" + log_name or ""

    log_dir = "logs"
    os.makedirs(log_dir, exist_ok=True)

    process = (
        connection.create_process(["type", "derpcli.log"])
        if connection.target_os == TargetOS.Windows
        else connection.create_process(["cat", "./derpcli.log"])
    )
    await process.execute()
    log_content = process.get_stdout()

    if connection.target_os == TargetOS.Linux:
        process = connection.create_process(["cat", "/etc/hostname"])
        await process.execute()
        container_id = process.get_stdout().strip()
    else:
        container_id = str(connection.target_os)

    test_name = test_name_safe_for_file_name()

    filename = str(test_name) + "_" + container_id + log_name + ".log"
    if len(filename.encode("utf-8")) > 256:
        filename = f"{filename[:251]}.log"

        i = 0
        while os.path.exists(os.path.join(log_dir, filename)):
            filename = f"{filename[:249]}_{i}.log"
            i += 1

    with open(
        os.path.join(log_dir, filename),
        "w",
        encoding="utf-8",
    ) as f:
        f.write(log_content)
