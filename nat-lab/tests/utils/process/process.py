from abc import ABC, abstractmethod
from contextlib import asynccontextmanager
from typing import List, Optional, Callable, Awaitable, AsyncIterator, Any

StreamCallback = Callable[[str], Awaitable[Any]]


class ProcessExecError(Exception):
    returncode: int
    cmd: List[str]
    stdout: str
    stderr: str

    def __init__(
        self, returncode: int, cmd: List[str], stdout: str, stderr: str
    ) -> None:
        self.returncode = returncode
        self.cmd = cmd
        self.stdout = stdout
        self.stderr = stderr

    def print(self) -> None:
        print(
            f"Executed command {self.cmd} exited with ret code '{self.returncode}'. STDOUT: '{self.stdout}'. STDERR: '{self.stderr}'"
        )


class Process(ABC):
    @abstractmethod
    async def execute(
        self,
        stdout_callback: Optional[StreamCallback] = None,
        stderr_callback: Optional[StreamCallback] = None,
    ) -> "Process":
        pass

    @abstractmethod
    @asynccontextmanager
    async def run(
        self,
        stdout_callback: Optional[StreamCallback] = None,
        stderr_callback: Optional[StreamCallback] = None,
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
