import asyncio
import asyncssh
from .process import Process, ProcessExecError, StreamCallback
from contextlib import asynccontextmanager
from tests.utils.asyncio_util import run_async_context
from tests.utils.logger import log
from typing import List, Optional, Callable, AsyncIterator


class SshProcess(Process):
    _ssh_connection: asyncssh.SSHClientConnection
    _vm_name: str
    _command: List[str]
    _stdout: str
    _stderr: str
    _stdin_ready: asyncio.Event
    _is_done: asyncio.Event
    _stdin: Optional[asyncssh.SSHWriter]
    _process: Optional[asyncssh.SSHClientProcess]
    _running: bool
    _term_type: Optional[str]

    def __init__(
        self,
        ssh_connection: asyncssh.SSHClientConnection,
        vm_name: str,
        command: List[str],
        escape_argument: Callable[[str], str],
        term_type: Optional[str] = None,
    ) -> None:
        self._ssh_connection = ssh_connection
        self._vm_name = vm_name
        self._command = command
        self._stdout = ""
        self._stderr = ""
        self._stdin_ready = asyncio.Event()
        self._is_done = asyncio.Event()
        self._stdin = None
        self._escape_argument = escape_argument
        self._process = None
        self._running = False
        self._term_type = term_type

    async def execute(
        self,
        stdout_callback: Optional[StreamCallback] = None,
        stderr_callback: Optional[StreamCallback] = None,
        privileged: bool = False,
    ) -> "SshProcess":
        if privileged:
            log.warning("'privileged' does nothing for ssh processes")
        escaped = [self._escape_argument(arg) for arg in self._command]
        command_str = " ".join(escaped)

        try:
            self._process = await self._ssh_connection.create_process(
                command_str, term_type=self._term_type
            )
            self._running = True
            self._stdin = self._process.stdin
            self._stdin_ready.set()

            await asyncio.gather(
                self._stdout_loop(self._process.stdout, stdout_callback),
                self._stderr_loop(self._process.stderr, stderr_callback),
            )
        except asyncio.CancelledError:
            log.debug("[%s] '%s' process cancelled.", self._vm_name, self._command)
            raise
        except:
            log.error("[%s] Exception thrown:", self._vm_name, exc_info=True)
            raise
        finally:
            if self._process and self._process.returncode is None:
                self._process.kill()
                self._process.close()
                await self._process.wait_closed()
            self._running = False

        await self._process.wait()

        returncode = self._process.returncode
        exit_status = self._process.exit_status
        exit_signal = self._process.exit_signal

        # 0 success
        if returncode and returncode != 0:
            err = ProcessExecError(
                returncode,
                self._vm_name,
                self._command,
                self._stdout,
                self._stderr,
                exit_status,
                exit_signal,
            )
            log.debug(
                "[%s] Command failed on %s: %s; returncode=%s exit_status=%s exit_signal=%s; "
                "stdout=%s; stderr=%s",
                self._vm_name,
                err.remote_name,
                command_str,
                err.returncode,
                err.exit_status,
                err.exit_signal,
                err.stdout,
                err.stderr,
            )
            raise err

        return self

    @asynccontextmanager
    async def run(
        self,
        stdout_callback: Optional[StreamCallback] = None,
        stderr_callback: Optional[StreamCallback] = None,
        privileged: bool = False,
    ) -> AsyncIterator["SshProcess"]:
        async def mark_as_done():
            try:
                await self.execute(stdout_callback, stderr_callback, privileged)
            finally:
                self._is_done.set()

        async with run_async_context(mark_as_done()):
            try:
                yield self
            finally:
                if self._process and self._process.returncode is None:
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

    async def wait_stdin_ready(self, timeout: Optional[float] = None) -> None:
        await asyncio.wait_for(self._stdin_ready.wait(), timeout)

    async def write_stdin(self, data: str) -> None:
        assert self._stdin, "process dead"
        self._stdin.write(data)

    async def escape_and_write_stdin(self, data: List[str]) -> None:
        escaped = [self._escape_argument(arg) for arg in data]
        command_str = " ".join(escaped) + "\n"
        await self.write_stdin(command_str)

    def get_stdout(self) -> str:
        return self._stdout

    def get_stderr(self) -> str:
        return self._stderr

    def is_executing(self) -> bool:
        return self._running

    async def is_done(self) -> None:
        await self._is_done.wait()
