import asyncio
import pytest
from helpers import SetupParameters
from telio import AdapterType
from typing import List, Tuple
from utils.connection_util import ConnectionTag, LAN_ADDR_MAP
from utils.router import IPStack
from utils.vm import windows_vm_util, mac_vm_util


def _cancel_all_tasks(loop: asyncio.AbstractEventLoop):
    to_cancel = asyncio.tasks.all_tasks(loop)
    if not to_cancel:
        return

    for task in to_cancel:
        task.print_stack()
        task.cancel()

    loop.run_until_complete(asyncio.tasks.gather(*to_cancel, return_exceptions=True))

    for task in to_cancel:
        if task.cancelled():
            continue
        if task.exception() is not None:
            loop.call_exception_handler({
                "message": "unhandled exception during asyncio.run() shutdown",
                "exception": task.exception(),
                "task": task,
            })


@pytest.fixture(scope="function")
def event_loop():
    loop = asyncio.get_event_loop_policy().new_event_loop()
    try:
        yield loop
    finally:
        try:
            _cancel_all_tasks(loop)
            loop.run_until_complete(loop.shutdown_asyncgens())
            loop.run_until_complete(loop.shutdown_default_executor())
        finally:
            asyncio.events.set_event_loop(None)
            loop.close()


def pytest_make_parametrize_id(config, val):
    param_id = ""
    if isinstance(val, (List, Tuple)):
        for v in val:
            res = pytest_make_parametrize_id(config, v)
            if isinstance(res, str) and res != "":
                param_id += f"-{res}"
        param_id = f"{param_id[1:]}"
    elif isinstance(val, (SetupParameters,)):
        short_conn_tag_name = val.connection_tag.name.removeprefix("DOCKER_")
        param_id = f"{short_conn_tag_name}-{val.adapter_type.name}"
        if (
            val.features.direct is not None
            and val.features.direct.providers is not None
        ):
            for provider in val.features.direct.providers:
                param_id += f"-{provider}"
    elif isinstance(val, (ConnectionTag,)):
        param_id = val.name.removeprefix("DOCKER_")
    elif isinstance(val, (AdapterType,)):
        param_id = val.name
    elif isinstance(val, IPStack):
        if val == IPStack.IPv4:
            param_id = "IPv4"
        elif val == IPStack.IPv4v6:
            param_id = "IPv4v6"
        elif val == IPStack.IPv6:
            param_id = "IPv6"
    elif isinstance(val, str):
        if len(val) > 16:
            param_id = f"{val[:14]}.."
        else:
            param_id = val
    else:
        return None
    return param_id


def pytest_collection_finish(session):
    async def copy_binaries():
        mac_vm, win_vm_1, win_vm_2 = False, False, False

        for item in session.items:
            if "WINDOWS_VM_1" in item.name:
                win_vm_1 = True

            if "WINDOWS_VM_2" in item.name:
                win_vm_2 = True

            if "MAC_VM" in item.name:
                mac_vm = True

        if win_vm_1:
            async with windows_vm_util.new_connection(
                LAN_ADDR_MAP[ConnectionTag.WINDOWS_VM_1], copy_binaries=True
            ):
                pass

        if win_vm_2:
            async with windows_vm_util.new_connection(
                LAN_ADDR_MAP[ConnectionTag.WINDOWS_VM_2], copy_binaries=True
            ):
                pass

        if mac_vm:
            async with mac_vm_util.new_connection(copy_binaries=True):
                pass

    asyncio.run(copy_binaries())
