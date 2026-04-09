import asyncio
import logging
import os
import Pyro5  # type: ignore
import pytest
import threading
from contextlib import AsyncExitStack
from tests.helpers import SetupParameters
from tests.helpers_log_collection import collect_logs, collect_kernel_logs
from tests.helpers_pretest import perform_pretest_cleanups, copy_vm_binaries_if_needed
from tests.helpers_setup_checks import (
    perform_setup_checks,
    check_gateway_connectivity,
    check_all_containers_running,
    get_session_vm_marks,
)
from tests.helpers_windows_monitoring import (
    start_tcpdump_processes,
    start_windows_vms_resource_monitoring,
)
from tests.log_collector import LOG_COLLECTORS
from tests.utils.bindings import TelioAdapterType
from tests.utils.connection import ConnectionTag
from tests.utils.connection_util import new_connection_raw
from tests.utils.logger import log
from tests.utils.router import IPStack
from tests.utils.testing import get_current_test_log_path
from typing import List

RUNNER: asyncio.Runner | None = None
SESSION_SCOPE_EXIT_STACK: AsyncExitStack | None = None
TASKS: List[asyncio.Task] = []
END_TASKS: threading.Event = threading.Event()
CURRENT_TEST_LOG_FILE = None

SESSION_VM_MARKS: set[str] = set()
SESSION_IS_CONTAINER_RUNNING: dict[ConnectionTag, bool] = {}


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


# Keep in mind that Windows can consider the filesize too big if parameters are not stripped
def pytest_make_parametrize_id(config, val):
    param_id = ""
    if isinstance(val, (list, tuple)):
        for v in val:
            res = pytest_make_parametrize_id(config, v)
            if isinstance(res, str) and res != "":
                param_id += f"-{res}"
        param_id = f"{param_id[1:]}"
    elif isinstance(val, (SetupParameters,)):
        short_conn_tag_name = val.connection_tag.name.removeprefix("DOCKER_")
        param_id = f"{short_conn_tag_name}-{val.adapter_type_override.name.replace('_', '') if val.adapter_type_override is not None else ''}"
        if (
            val.features.direct is not None
            and val.features.direct.providers is not None
        ):
            for provider in val.features.direct.providers:
                param_id += f"-{provider.name}"
    elif isinstance(val, (ConnectionTag,)):
        param_id = val.name.removeprefix("DOCKER_")
    elif isinstance(val, (TelioAdapterType,)):
        param_id = val.name.replace("_", "")
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


def pytest_collection_modifyitems(items):
    for item in items:
        # Apply 5 minutes timeout to windows tests (due to constant lag)
        if item.get_closest_marker("windows"):
            item.add_marker(pytest.mark.timeout(300))


def pytest_runtestloop(session):
    global SESSION_VM_MARKS, SESSION_IS_CONTAINER_RUNNING

    if session.config.option.collectonly:
        return

    SESSION_VM_MARKS = get_session_vm_marks(session.items)

    if "NATLAB_SKIP_SETUP_CHECKS" not in os.environ:
        SESSION_IS_CONTAINER_RUNNING = asyncio.run(check_all_containers_running())

        if not asyncio.run(
            perform_setup_checks(SESSION_IS_CONTAINER_RUNNING, SESSION_VM_MARKS)
        ):
            pytest.exit("Setup checks failed, exiting ...")

    if "NATLAB_SAVE_LOGS" in os.environ:
        asyncio.run(
            collect_kernel_logs(
                "before_tests",
                SESSION_VM_MARKS,
            )
        )

    asyncio.run(copy_vm_binaries_if_needed(SESSION_VM_MARKS))


def pytest_runtest_setup():
    asyncio.run(perform_pretest_cleanups())


def pytest_runtest_teardown(item, nextitem):  # pylint: disable=unused-argument
    if os.environ.get("NATLAB_SAVE_LOGS") is None:
        return

    log.info(
        "Running post-test log collection for %s, tasks: %d",
        item.reportinfo()[2],
        len(LOG_COLLECTORS),
    )

    assert RUNNER

    async def collect_all_logs():
        async with AsyncExitStack() as stack:
            for log_collector in LOG_COLLECTORS:
                log.info(
                    "[%s] Will run post-test log collection for %s",
                    log_collector.node_name,
                    log_collector.tag,
                )
                connection = await stack.enter_async_context(
                    new_connection_raw(log_collector.tag)
                )
                await log_collector.cleanup(connection)
                log.info(
                    "[%s] Done running post-test log collection for %s",
                    log_collector.node_name,
                    log_collector.tag,
                )

    RUNNER.run(collect_all_logs())

    LOG_COLLECTORS.clear()
    global CURRENT_TEST_LOG_FILE

    if CURRENT_TEST_LOG_FILE:
        CURRENT_TEST_LOG_FILE.flush()
        log.removeHandler(CURRENT_TEST_LOG_FILE)
        CURRENT_TEST_LOG_FILE.close()

    CURRENT_TEST_LOG_FILE = None

    log.info("Post-test log collection completed for %s", item.reportinfo()[2])


# Session-long AsyncExitStack is created at session start and closed at session finish.
# pylint: disable=unused-argument
def pytest_sessionstart(session):
    global RUNNER, SESSION_SCOPE_EXIT_STACK
    setattr(Pyro5.config, "SERPENT_BYTES_REPR", True)
    if os.environ.get("NATLAB_SAVE_LOGS"):
        RUNNER = asyncio.Runner()
        SESSION_SCOPE_EXIT_STACK = AsyncExitStack()
        if not RUNNER.run(check_gateway_connectivity(SESSION_SCOPE_EXIT_STACK)):
            pytest.exit("Gateway nodes connectivity check failed, exiting ...")
        RUNNER.run(
            start_tcpdump_processes(
                SESSION_SCOPE_EXIT_STACK,
            )
        )
        RUNNER.run(start_windows_vms_resource_monitoring(TASKS, END_TASKS))


# pylint: disable=unused-argument
def pytest_sessionfinish(session, exitstatus):
    if os.environ.get("NATLAB_SAVE_LOGS") is None or session.config.option.collectonly:
        return

    END_TASKS.set()

    if RUNNER is not None:
        try:
            if SESSION_SCOPE_EXIT_STACK is not None:
                RUNNER.run(SESSION_SCOPE_EXIT_STACK.aclose())
        finally:
            RUNNER.close()

    asyncio.run(collect_logs(SESSION_VM_MARKS))


@pytest.fixture(autouse=True)
def setup_logger(tmp_path, request):
    file_handler = None
    if os.environ.get("NATLAB_SAVE_LOGS"):
        log_dir = get_current_test_log_path()
        os.makedirs(log_dir, exist_ok=True)
        log_file = os.path.join(log_dir, "debug.log")

        file_handler = logging.FileHandler(log_file, mode="w")
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(
            logging.Formatter("%(asctime)s,%(msecs)03d | %(levelname)s %(message)s")
        )
        log.addHandler(file_handler)

        global CURRENT_TEST_LOG_FILE
        CURRENT_TEST_LOG_FILE = file_handler
    try:
        yield
    finally:
        pass
