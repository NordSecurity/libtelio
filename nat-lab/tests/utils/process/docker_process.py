from aiodocker.containers import DockerContainer
from aiodocker.stream import Stream
from aiodocker.execs import Exec
from utils.process import Process, ProcessExecError, StreamCallback
from utils.asyncio_util import run_async_context
from typing import List, Optional, AsyncIterator
from contextlib import suppress, asynccontextmanager
import asyncio
import sys
import os


class DockerProcess(Process):
    _container: DockerContainer
    _command: List[str]
    _stdout: str
    _stderr: str
    _allowed_exit_codes: List[int]
    _stdin_ready: asyncio.Event
    _stream: Optional[Stream]
    _execute: Optional[Exec]

    def __init__(self, container: DockerContainer, command: List[str]) -> None:
        self._container = container
        self._command = command
        self._stdout = ""
        self._stderr = ""
        self._stdin_ready = asyncio.Event()
        self._stream = None
        self._execute = None

    async def execute(
        self,
        stdout_callback: Optional[StreamCallback] = None,
        stderr_callback: Optional[StreamCallback] = None,
    ) -> "DockerProcess":
        self._execute = await self._container.exec(self._command, stdin=True)
        if self._execute is None:
            return self
        async with self._execute.start() as exe_stream:
            self._stream = exe_stream
            self._stdin_ready.set()
            await self._read_loop(exe_stream, stdout_callback, stderr_callback)
            self._stream = None

        inspect = await self._execute.inspect()
        exit_code = inspect["ExitCode"]

        # we ignore 143 (SIGTERM), since sometimes we kill processes ourselfs
        if exit_code not in [0, 143]:
            raise ProcessExecError(exit_code, self._command, self._stdout, self._stderr)

        return self

    @asynccontextmanager
    async def run(
        self,
        stdout_callback: Optional[StreamCallback] = None,
        stderr_callback: Optional[StreamCallback] = None,
    ) -> AsyncIterator["DockerProcess"]:
        async with run_async_context(self.execute(stdout_callback, stderr_callback)):
            try:
                yield self
            finally:
                if self._execute:
                    with suppress(Exception):
                        inspect = await self._execute.inspect()
                        while inspect["Pid"] == 0:
                            inspect = await self._execute.inspect()
                            await asyncio.sleep(0.01)
                        if inspect["ExitCode"] is None:
                            os.system(f"sudo kill -9 {inspect['Pid']}")

    async def _read_loop(
        self,
        stream: Stream,
        stdout_callback: Optional[StreamCallback] = None,
        stderr_callback: Optional[StreamCallback] = None,
    ) -> None:
        buffers = {1: bytearray(), 2: bytearray()}
        while True:
            message = await stream.read_out()
            if message is None:
                break

            if message.stream != 1 and message.stream != 2:
                raise ValueError(f"unknown stream {message.stream}")

            buffers[message.stream] += message.data

            if b"\x0A" not in buffers[message.stream]:
                continue

            lines = buffers[message.stream].split(b"\x0A")
            if b"\x0A" in lines[-1]:
                decodeable_lines = lines
                buffers[message.stream] = bytearray()
            else:
                buffers[message.stream] = lines[-1]
                if len(lines) <= 1:
                    continue
                decodeable_lines = lines[:-1]

            output = b"\x0A".join(decodeable_lines).decode(sys.getfilesystemencoding())

            if message.stream == 1:
                self._stdout += output
                if stdout_callback:
                    await stdout_callback(output)
            elif message.stream == 2:
                self._stderr += output
                if stderr_callback:
                    await stderr_callback(output)

        for stream_id, buffer in buffers.items():
            if buffer:
                output = buffer.decode(sys.getfilesystemencoding(), errors="ignore")
                if stream_id == 1:
                    self._stdout += output
                    if stdout_callback:
                        await stdout_callback(output)
                elif stream_id == 2:
                    self._stderr += output
                    if stderr_callback:
                        await stderr_callback(output)

    async def wait_stdin_ready(self) -> None:
        await self._stdin_ready.wait()

    async def write_stdin(self, data: str) -> None:
        assert self._stream, "process dead"
        await self._stream.write_in(data.encode("utf-8"))

    def get_stdout(self) -> str:
        return self._stdout

    def get_stderr(self) -> str:
        return self._stderr
