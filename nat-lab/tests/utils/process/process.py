from abc import ABC, abstractmethod
from typing import List, Optional, Callable, Awaitable, AsyncIterator
from contextlib import asynccontextmanager

StreamCallback = Callable[[str], Awaitable[None]]


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
    async def wait_stdin_ready(self) -> None:
        pass

    @abstractmethod
    async def write_stdin(self, data: str) -> None:
        pass

    @abstractmethod
    def get_stdout(self) -> str:
        pass

    @abstractmethod
    def get_stderr(self) -> str:
        pass
