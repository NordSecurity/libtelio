import asyncio
import secrets
import sys
from .process import Process, ProcessExecError, StreamCallback
from aiodocker.containers import DockerContainer
from aiodocker.execs import Exec
from aiodocker.stream import Stream
from contextlib import asynccontextmanager
from tests.utils.asyncio_util import run_async_context
from tests.utils.logger import log
from tests.utils.moose import MOOSE_LOGS_DIR
from typing import List, Optional, AsyncIterator

_PROCESS_START_TIMEOUT = 10.0  # seconds to wait for exec PID to appear

# Exit codes for processes terminated by a signal: 128 + signal number
_EXIT_CODE_SIGKILL = 137  # 128 + 9 (SIGKILL)
_EXIT_CODE_SIGTERM = 143  # 128 + 15 (SIGTERM)


class DockerProcess(Process):
    _container: DockerContainer
    _container_name: str
    _command: List[str]
    _stdout: str
    _stderr: str
    _allowed_exit_codes: List[int]
    _stdin_ready: asyncio.Event
    _is_done: asyncio.Event
    _stream: Optional[Stream]
    _execute: Optional[Exec]
    _kill_id: (
        str  # Private ID added to find the process easily when it needs to be killed
    )
    _kill_sent: bool  # Set to True once an intentional kill has been dispatched

    def __init__(
        self,
        container: DockerContainer,
        container_name: str,
        command: List[str],
        kill_id=None,
    ) -> None:
        self._container = container
        self._container_name = container_name
        self._command = command
        self._stdout = ""
        self._stderr = ""
        self._stdin_ready = asyncio.Event()
        self._is_done = asyncio.Event()
        self._stream = None
        self._execute = None
        self._kill_id = kill_id if kill_id else secrets.token_hex(8).upper()
        self._kill_sent = False

    async def execute(
        self,
        stdout_callback: Optional[StreamCallback] = None,
        stderr_callback: Optional[StreamCallback] = None,
        privileged: bool = False,
    ) -> "DockerProcess":
        try:
            self._execute = await self._container.exec(
                self._command,
                stdin=True,
                environment={
                    "MOOSE_LOG": "Trace",
                    "MOOSE_LOG_FILE": MOOSE_LOGS_DIR,
                    "RUST_BACKTRACE": "full",
                    "KILL_ID": self._kill_id,
                    "LD_LIBRARY_PATH": "/libtelio/nat-lab/tests/uniffi",
                },
                privileged=privileged,
            )
        except:
            log.error("[%s] Exception thrown:", self._container_name, exc_info=True)
            raise
        if self._execute is None:
            return self
        async with self._execute.start() as exe_stream:
            self._stream = exe_stream
            self._stdin_ready.set()
            try:
                await self._read_loop(exe_stream, stdout_callback, stderr_callback)
            except asyncio.CancelledError:
                log.debug(
                    "[%s] '%s' process cancelled.", self._container_name, self._command
                )
                raise
            except:
                log.error("[%s] Exception thrown:", self._container_name, exc_info=True)
                raise
            finally:
                if self._execute:
                    await self._kill_exec_if_running()
                self._stream = None

        try:
            inspect = await self._execute.inspect()
        except RuntimeError as e:
            if "Session is closed" in str(e):
                log.debug(
                    "[%s] Docker session closed during cleanup",
                    self._container_name,
                )
                return self
            raise
        exit_code = inspect["ExitCode"]

        # 0  — clean exit
        # 137 (SIGKILL) / 143 (SIGTERM) — expected only when we dispatched
        # an intentional kill via _kill_exec_if_running(); an unexpected
        # SIGTERM from outside should still surface as an error.
        intentional_kill = self._kill_sent and exit_code in (
            _EXIT_CODE_SIGKILL,
            _EXIT_CODE_SIGTERM,
        )
        if exit_code and not intentional_kill:
            raise ProcessExecError(
                exit_code,
                self._container_name,
                self._command,
                self._stdout,
                self._stderr,
            )

        return self

    async def _wait_for_process_start(self) -> dict:
        """Poll exec inspect until a PID or exit code appears.

        Raises ``asyncio.TimeoutError`` if the process does not start
        within ``_PROCESS_START_TIMEOUT`` seconds.
        """
        assert self._execute is not None
        execute = self._execute

        async def _poll() -> dict:
            while True:
                info = await execute.inspect()
                if info["Pid"] != 0 or info["ExitCode"] is not None:
                    return info
                await asyncio.sleep(0.01)

        return await asyncio.wait_for(_poll(), timeout=_PROCESS_START_TIMEOUT)

    async def _kill_exec_if_running(self) -> None:
        """Wait for the exec to start, then kill it if it hasn't exited."""
        try:
            info = await self._wait_for_process_start()
            if info["ExitCode"] is None:
                self._kill_sent = True
                proc = await asyncio.create_subprocess_exec(
                    "docker",
                    "exec",
                    "--privileged",
                    self._container.id,
                    "/opt/bin/kill_process_by_natlab_id",
                    self._kill_id,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                stdout, stderr = await proc.communicate()
                if proc.returncode != 0:
                    log.warning(
                        "[%s] Cleanup failed: %s",
                        self._container_name,
                        (stdout or b"").decode() + (stderr or b"").decode(),
                    )
        except asyncio.TimeoutError:
            log.warning(
                "[%s] Timed out waiting for exec process to start during cleanup",
                self._container_name,
            )
        except RuntimeError as e:
            if "Session is closed" in str(e):
                log.debug(
                    "[%s] Docker session closed during cleanup",
                    self._container_name,
                )
            else:
                raise

    @asynccontextmanager
    async def run(
        self,
        stdout_callback: Optional[StreamCallback] = None,
        stderr_callback: Optional[StreamCallback] = None,
        privileged: bool = False,
    ) -> AsyncIterator["DockerProcess"]:
        async def mark_as_done():
            try:
                await self.execute(stdout_callback, stderr_callback, privileged)
            finally:
                self._is_done.set()

        async with run_async_context(mark_as_done()):
            try:
                yield self
            finally:
                if self._execute:
                    await self._kill_exec_if_running()

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

            if message.stream not in (1, 2):
                raise ValueError(f"unknown stream {message.stream}")

            buffers[message.stream] += message.data

            if b"\x0a" not in buffers[message.stream]:
                continue

            lines = buffers[message.stream].split(b"\x0a")
            if b"\x0a" in lines[-1]:
                decodeable_lines = lines
                buffers[message.stream] = bytearray()
            else:
                buffers[message.stream] = lines[-1]
                if len(lines) <= 1:
                    continue
                decodeable_lines = lines[:-1]

            output = b"\x0a".join(decodeable_lines).decode(
                sys.getfilesystemencoding(), errors="replace"
            )

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
                output = buffer.decode(sys.getfilesystemencoding(), errors="replace")
                if stream_id == 1:
                    self._stdout += output
                    if stdout_callback:
                        await stdout_callback(output)
                elif stream_id == 2:
                    self._stderr += output
                    if stderr_callback:
                        await stderr_callback(output)

    async def wait_stdin_ready(self, timeout: Optional[float] = None) -> None:
        await asyncio.wait_for(self._stdin_ready.wait(), timeout)

    async def write_stdin(self, data: str) -> None:
        assert self._stream, "process dead"
        await self._stream.write_in(data.encode("utf-8"))

    async def escape_and_write_stdin(self, data: List[str]) -> None:
        command_str = " ".join(data) + "\n"
        await self.write_stdin(command_str)

    def get_stdout(self) -> str:
        return self._stdout

    def get_stderr(self) -> str:
        return self._stderr

    def is_executing(self) -> bool:
        return self._stream is not None

    async def is_done(self) -> None:
        await self._is_done.wait()
