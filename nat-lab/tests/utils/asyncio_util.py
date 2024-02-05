from asyncio import Task, Future, ensure_future, CancelledError
from contextlib import asynccontextmanager
from typing import AsyncIterator, Coroutine, List, Union


@asynccontextmanager
async def run_async_context(coroutine: Union[Coroutine, Future]) -> AsyncIterator[Task]:
    future = ensure_future(coroutine)
    try:
        yield future
    finally:
        await cancel_future(future)


@asynccontextmanager
async def run_async_contexts(
    coroutines: List[Union[Coroutine, Future]]
) -> AsyncIterator[List[Task]]:
    futures = [ensure_future(coroutine) for coroutine in coroutines]
    try:
        yield futures
    finally:
        for future in futures:
            await cancel_future(future)


async def cancel_future(future: Future) -> None:
    future.cancel()
    try:
        await future
    except CancelledError:
        # Future always raises 'asyncio.CancelledError' after its cancelled. Swallowing
        # this exception is the expected behaviour, since the future was just cancelled.
        pass
