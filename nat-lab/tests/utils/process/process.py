from abc import ABC, abstractmethod
from contextlib import asynccontextmanager

# the single exception type, shared with natlab: natlab's own tools catch its class,
# so a second one of the same shape here makes every `except ProcessExecError` in the
# framework - allow_process_failure above all - silently miss
from natlab.process import (  # noqa: F401  # pylint: disable=unused-import
    ProcessExecError,
)
from typing import List, Optional, Callable, Awaitable, AsyncIterator, Any

StreamCallback = Callable[[str], Awaitable[Any]]


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
