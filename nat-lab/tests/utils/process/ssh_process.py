from utils.process import Process, ProcessExecError, StreamCallback
from utils.asyncio_util import run_async_context
from typing import List, Optional, Callable, AsyncIterator
import asyncio
import asyncssh
from contextlib import suppress, asynccontextmanager


class SshProcess(Process):
    _ssh_connection: asyncssh.SSHClientConnection
    _command: List[str]
    _stdout: str
    _stderr: str
    _stdin_ready: asyncio.Event
    _stdin: Optional[asyncssh.SSHWriter]

    def __init__(
        self,
        ssh_connection: asyncssh.SSHClientConnection,
        command: List[str],
        escape_argument: Callable[[str], str],
    ) -> None:
        self._ssh_connection = ssh_connection
        self._command = command
        self._stdout = ""
        self._stderr = ""
        self._stdin_ready = asyncio.Event()
        self._stdin = None
        self._escape_argument = escape_argument

    async def execute(
        self,
        stdout_callback: Optional[StreamCallback] = None,
        stderr_callback: Optional[StreamCallback] = None,
    ) -> "SshProcess":
        escaped = [self._escape_argument(arg) for arg in self._command]
        command_str = " ".join(escaped)

        self._process = await self._ssh_connection.create_process(command_str)
        self._stdin = self._process.stdin
        self._stdin_ready.set()

        await asyncio.gather(
            self._stdout_loop(self._process.stdout, stdout_callback),
            self._stderr_loop(self._process.stderr, stderr_callback),
        )

        completed_process: asyncssh.SSHCompletedProcess = await self._process.wait()
        assert completed_process.returncode is not None
        if completed_process.returncode != 0:
            raise ProcessExecError(
                completed_process.returncode,
                self._command,
                self._stdout,
                self._stderr,
            )

        return self

    @asynccontextmanager
    async def run(
        self,
        stdout_callback: Optional[StreamCallback] = None,
        stderr_callback: Optional[StreamCallback] = None,
    ) -> AsyncIterator["SshProcess"]:
        async with run_async_context(self.execute(stdout_callback, stderr_callback)):
            try:
                yield self
            finally:
                with suppress(Exception):
                    if self._process.returncode is None:
                        self._process.kill()
                        self._process.close()
                        await self._process.wait_closed()

    async def _stdout_loop(
        self, stdout: asyncssh.SSHReader, stdout_callback: Optional[StreamCallback]
    ) -> None:
        while True:
            line = await stdout.readline()
            if line:
                self._stdout += line
                if stdout_callback:
                    await stdout_callback(line)
            else:
                break

    async def _stderr_loop(
        self, stderr: asyncssh.SSHReader, stderr_callback: Optional[StreamCallback]
    ) -> None:
        while True:
            line = await stderr.readline()
            if line:
                self._stderr += line
                if stderr_callback:
                    await stderr_callback(line)
            else:
                break

    async def wait_stdin_ready(self) -> None:
        await self._stdin_ready.wait()

    async def write_stdin(self, data: str) -> None:
        assert self._stdin, "process dead"
        self._stdin.write(data)

    def get_stdout(self) -> str:
        return self._stdout

    def get_stderr(self) -> str:
        return self._stderr
