import asyncio
from contextlib import asynccontextmanager
from typing import AsyncIterator, Coroutine, List


@asynccontextmanager
async def run_async_context(coroutine: Coroutine) -> AsyncIterator[asyncio.Future]:
    future = asyncio.ensure_future(coroutine)
    try:
        yield future
    finally:
        await cancel_future(future)


@asynccontextmanager
async def run_async_contexts(
    coroutines: List[Coroutine],
) -> AsyncIterator[List[asyncio.Future]]:
    futures: List[asyncio.Future] = [
        asyncio.ensure_future(coroutine) for coroutine in coroutines
    ]
    try:
        yield futures
    finally:
        for future in futures:
            await cancel_future(future)


async def cancel_future(future: asyncio.Future) -> None:
    future.cancel()
    try:
        await future
    except asyncio.CancelledError:
        # Future always raises 'asyncio.CancelledError' after its cancelled. Swallowing
        # this exception is the expected behaviour, since the future was just cancelled.
        pass
