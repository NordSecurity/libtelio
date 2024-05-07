import asyncio
import os
from asyncio import Future
from typing import Union, Coroutine, Optional, TypeVar, Any

# This modules defines standardized waiting categories for tests. Some tasks are expected
# to finish very quickly, hence the waiting time is very short (0.1 seconds). Other tasks
# are expected to take more time, so the waiting time is much longer (5 seconds).

T = TypeVar("T")


async def wait_short(coroutine: Union[Coroutine[Any, Any, T], Future]) -> T:
    """Wait for 0.1 seconds"""
    return await asyncio.wait_for(coroutine, 0.1)


async def wait_normal(coroutine: Union[Coroutine[Any, Any, T], Future]) -> T:
    """Wait for 1 second"""
    return await asyncio.wait_for(coroutine, 1)


async def wait_long(coroutine: Union[Coroutine[Any, Any, T], Future]) -> T:
    """Wait for 5 seconds"""
    return await asyncio.wait_for(coroutine, 5)


async def wait_lengthy(coroutine: Union[Coroutine[Any, Any, T], Future]) -> T:
    """Wait for 30 seconds"""
    return await asyncio.wait_for(coroutine, 30)


async def wait_defined(
    coroutine: Union[Coroutine[Any, Any, T], Future], defined_wait
) -> T:
    """Wait for defined seconds"""
    return await asyncio.wait_for(coroutine, defined_wait)


def unpack_optional(opt: Optional[T]) -> T:
    if opt is None:
        raise ValueError("Optional value is None")
    return opt


def test_name_safe_for_file_name():
    test_name = os.environ.get("PYTEST_CURRENT_TEST")
    if test_name is not None:
        return "".join([x if x.isalnum() else "_" for x in test_name.split(" ")[0]])
    return test_name
