from utils.process import Process, ProcessExecError, StreamCallback
from utils import asyncio_util
from typing import List, Optional, Callable
import asyncio
import asyncssh


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

        process = await self._ssh_connection.create_process(command_str)

        self._stdin = process.stdin
        self._stdin_ready.set()

        future_stdout = asyncio_util.run_async(
            self._stdout_loop(process.stdout, stdout_callback)
        )
        future_stderr = asyncio_util.run_async(
            self._stderr_loop(process.stderr, stderr_callback)
        )

        await future_stdout
        await future_stderr

        completed_process: asyncssh.SSHCompletedProcess = await process.wait()
        assert completed_process.returncode is not None
        if completed_process.returncode != 0:
            raise ProcessExecError(
                completed_process.returncode, self._command, self._stdout, self._stderr
            )

        return self

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
