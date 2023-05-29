from contextlib import asynccontextmanager
from typing import AsyncIterator, Coroutine
import asyncio
import sys

# This function is magical fairy dust. Its meant to be used as a replacement for
# asyncio.ensure_future(create_task since 3.7). The main purpose of this wrapper
# is fix error reporting when running unawaited futures under pytest.
#
# Pytest's asyncio expects that all futures will be awaited. Until the future is
# awaited, there will be no error logs for exceptions thrown inside the future.
# This raises a problem, because having to await a future means its not possible to
# trully start an async task.
#
# In some cases, spawning a long living coroutine without joining it is a very
# desired and useful behaviour. For example, spawning a long living task to read from
# socket, and continuing the main path of the program without awaiting for long
# living task.
#
# Using asyncio.ensure_future to spawn an unawaited task kind of works, but has
# a major issue. Any exceptions thrown in the task will be silently eaten up by pytest.
# This makes it impossible to debug trivial exceptions, such as typos, inside the
# unawaited task. Also, the test case passes without giving any indication of a
# possible failure.
#
# The magical fix is to use sys.exit(1) to exit in case an exception was thrown. This
# causes pytest to fail the currently running test and show useful stacktraces to make
# it possible to debug exceptions that happened inside the unawaited task.
def run_async(coroutine: Coroutine) -> asyncio.Future:
    async def wrap() -> None:
        try:
            await coroutine

        except asyncio.CancelledError as exception:
            # asyncio.CancelledError is part of normal program flow. Cancelling in-progress
            # futures is going to raise this exception, and so this exception must not be
            # treated as a fatal error.
            # Because of this, its possible to make use of python's mechanism to propagate
            # CancelledError through nested futures, without having to explicitly cancel
            # nested futures. Nested future meaning a future that has been created by
            # another future that is being cancelled.
            raise exception

        except:
            # Exiting like this causes pytest to print accurate and pretty logs.
            sys.exit(1)

    return asyncio.ensure_future(wrap())


@asynccontextmanager
async def run_async_context(coroutine: Coroutine) -> AsyncIterator[asyncio.Future]:
    future = run_async(coroutine)
    try:
        yield future
    finally:
        await cancel_future(future)


# Cancel a future that has been created with `asyncio_util.run_async`.
async def cancel_future(future: asyncio.Future) -> None:
    future.cancel()
    try:
        await future
    except asyncio.CancelledError:
        # Future always raises 'asyncio.CancelledError' after its cancelled. Swallowing
        # this exception is the expected behaviour, since the future was just cancelled.
        pass
