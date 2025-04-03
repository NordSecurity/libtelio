from abc import ABC, abstractmethod
from contextlib import asynccontextmanager
from typing import List, Optional, Callable, Awaitable, AsyncIterator, Any
from utils.logger import log

StreamCallback = Callable[[str], Awaitable[Any]]


class ProcessExecError(Exception):
    returncode: int
    remote_name: str
    cmd: List[str]
    stdout: str
    stderr: str

    def __init__(
        self,
        returncode: int,
        remote_name: str,
        cmd: List[str],
        stdout: str,
        stderr: str,
    ) -> None:
        self.returncode = returncode
        self.remote_name = remote_name
        self.cmd = cmd
        self.stdout = stdout
        self.stderr = stderr

    def print(self) -> None:
        log.error(
            "Executed command %s on %s exited with ret code '%s'. STDOUT: '%s'. STDERR: '%s'",
            " ".join(self.cmd),
            self.remote_name,
            self.returncode,
            self.stdout,
            self.stderr,
        )


class Process(ABC):
    @abstractmethod
    async def execute(
        self,
        stdout_callback: Optional[StreamCallback] = None,
        stderr_callback: Optional[StreamCallback] = None,
        privileged: bool = False,
    ) -> "Process":
        pass

    @abstractmethod
    @asynccontextmanager
    async def run(
        self,
        stdout_callback: Optional[StreamCallback] = None,
        stderr_callback: Optional[StreamCallback] = None,
        privileged: bool = False,
    ) -> AsyncIterator["Process"]:
        yield self

    @abstractmethod
    async def wait_stdin_ready(self, timeout: Optional[float] = None) -> None:
        pass

    @abstractmethod
    async def write_stdin(self, data: str) -> None:
        pass

    @abstractmethod
    async def escape_and_write_stdin(self, data: List[str]) -> None:
        pass

    @abstractmethod
    def get_stdout(self) -> str:
        pass

    @abstractmethod
    def get_stderr(self) -> str:
        pass

    @abstractmethod
    def is_executing(self) -> bool:
        pass

    @abstractmethod
    async def is_done(self) -> None:
        pass
