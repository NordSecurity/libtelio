# Register helpers_fixtures once here so individual test modules don't need to
# repeat it (which caused PytestWarning: Plugin already registered).
import asyncio
import logging
import os
import Pyro5  # type: ignore
import pytest
import threading
from contextlib import AsyncExitStack
from dataclasses import dataclass, field
from tests.conftest_helpers.log_collection import collect_logs, collect_kernel_logs
from tests.conftest_helpers.pretest import (
    perform_pretest_cleanups,
    copy_vm_binaries_if_needed,
    start_tcpdump_processes,
)
from tests.conftest_helpers.setup_checks import (
    perform_setup_checks,
    check_gateway_connectivity,
    check_all_containers_running,
    get_session_vm_marks,
)
from tests.conftest_helpers.windows_monitoring import (
    start_windows_vms_resource_monitoring,
)
from tests.helpers import SetupParameters
from tests.log_collector import LOG_COLLECTORS
from tests.utils.bindings import TelioAdapterType
from tests.utils.connection import ConnectionTag
from tests.utils.connection_util import new_connection_raw
from tests.utils.logger import log
from tests.utils.router import IPStack
from tests.utils.testing import get_current_test_log_path
from typing import List

pytest_plugins = ["tests.helpers_fixtures"]

DERP_SERVER_1_ADDR = "http://10.0.10.1:8765"
DERP_SERVER_2_ADDR = "http://10.0.10.2:8765"
DERP_SERVER_3_ADDR = "http://10.0.10.3:8765"
DERP_SERVER_1_SECRET_KEY = "yBTYHj8yPlG9VtMYMwJSRHdzNdyAlVXGc6X2xJkjfHQ="
DERP_SERVER_2_SECRET_KEY = "2NgALOCSKJcDxwr8MtA+6lYbf7b98KSdAROGoUwZ1V0="

SETUP_CHECK_TIMEOUT_S = 30
SETUP_CHECK_RETRIES = 5
SETUP_CHECK_CONNECTIVITY_TIMEOUT = 60
SETUP_CHECK_CONNECTIVITY_RETRIES = 1
GW_CHECK_CONNECTIVITY_TIMEOUT = 30
GW_CHECK_CONNECTIVITY_RETRIES = 2
SETUP_CHECK_MAC_COLLISION_TIMEOUT_S = 300
SETUP_CHECK_MAC_COLLISION_RETRIES = 1
SETUP_CHECK_ARP_CACHE_TIMEOUT_S = 300
SETUP_CHECK_ARP_CACHE_RETRIES = 1
SETUP_CHECK_DUPLICATE_IP_TIMEOUT_S = 60
SETUP_CHECK_DUPLICATE_IP_RETRIES = 1

TASKS: List[asyncio.Task] = []
END_TASKS: threading.Event = threading.Event()
_LIBFIREWALL_SO = os.path.join(os.path.dirname(__file__), "uniffi", "libfirewall.so")


@dataclass
class _SessionState:
    # Session-scoped singletons shared across pytest hooks. Grouping them in one
    # module-level object lets the hooks mutate shared state through attributes
    # instead of rebinding module globals (which would each need a `global`
    # statement).
    runner: asyncio.Runner | None = None
    exit_stack: AsyncExitStack | None = None
    current_test_log_file: logging.FileHandler | None = None
    vm_marks: set[str] = field(default_factory=set)


_SESSION = _SessionState()


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
def _setup_parameters_id(val: SetupParameters) -> str:
    short_conn_tag_name = val.connection_tag.name.removeprefix("DOCKER_")
    param_id = f"{short_conn_tag_name}-{val.adapter_type_override.name.replace('_', '') if val.adapter_type_override is not None else ''}"
    if val.features.direct is not None and val.features.direct.providers is not None:
        for provider in val.features.direct.providers:
            param_id += f"-{provider.name}"
    return param_id


def _ipstack_id(val: IPStack) -> str:
    return {
        IPStack.IPv4: "IPv4",
        IPStack.IPv4v6: "IPv4v6",
        IPStack.IPv6: "IPv6",
    }.get(val, "")


def pytest_make_parametrize_id(config, val):
    param_id = ""
    if isinstance(val, (list, tuple)):
        for v in val:
            res = pytest_make_parametrize_id(config, v)
            if isinstance(res, str) and res != "":
                param_id += f"-{res}"
        param_id = f"{param_id[1:]}"
    elif isinstance(val, (SetupParameters,)):
        param_id = _setup_parameters_id(val)
    elif isinstance(val, (ConnectionTag,)):
        param_id = val.name.removeprefix("DOCKER_")
    elif isinstance(val, (TelioAdapterType,)):
        param_id = val.name.replace("_", "")
    elif isinstance(val, IPStack):
        param_id = _ipstack_id(val)
    elif isinstance(val, str):
        if len(val) > 16:
            param_id = f"{val[:14]}.."
        else:
            param_id = val
    else:
        return None
    return param_id


def pytest_collection_modifyitems(items):
    libfirewall_missing = not os.path.exists(_LIBFIREWALL_SO)
    for item in items:
        # Apply 5 minutes timeout to windows tests (due to constant lag)
        if item.get_closest_marker("windows"):
            item.add_marker(pytest.mark.timeout(300))
        if libfirewall_missing and item.get_closest_marker("libfirewall"):
            item.add_marker(pytest.mark.skip(reason="libfirewall.so not available"))


def pytest_runtestloop(session):
    if session.config.option.collectonly:
        return

    _SESSION.vm_marks = get_session_vm_marks(session.items)

    if "NATLAB_SKIP_SETUP_CHECKS" not in os.environ:
        is_container_running: dict[ConnectionTag, bool] = asyncio.run(
            check_all_containers_running()
        )

        if not asyncio.run(
            perform_setup_checks(is_container_running, _SESSION.vm_marks)
        ):
            pytest.exit("Setup checks failed, exiting ...")

    if "NATLAB_SAVE_LOGS" in os.environ:
        asyncio.run(
            collect_kernel_logs(
                "before_tests",
                _SESSION.vm_marks,
            )
        )

    asyncio.run(copy_vm_binaries_if_needed(_SESSION.vm_marks))


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

    assert _SESSION.runner

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

    _SESSION.runner.run(collect_all_logs())

    LOG_COLLECTORS.clear()

    if _SESSION.current_test_log_file:
        _SESSION.current_test_log_file.flush()
        log.removeHandler(_SESSION.current_test_log_file)
        _SESSION.current_test_log_file.close()

    _SESSION.current_test_log_file = None

    log.info("Post-test log collection completed for %s", item.reportinfo()[2])


# Session-long AsyncExitStack is created at session start and closed at session finish.
# pylint: disable=unused-argument
def pytest_sessionstart(session):
    setattr(Pyro5.config, "SERPENT_BYTES_REPR", True)
    if os.environ.get("NATLAB_SAVE_LOGS"):
        _SESSION.runner = asyncio.Runner()
        _SESSION.exit_stack = AsyncExitStack()
        if not _SESSION.runner.run(check_gateway_connectivity(_SESSION.exit_stack)):
            pytest.exit("Gateway nodes connectivity check failed, exiting ...")
        _SESSION.runner.run(
            start_tcpdump_processes(
                _SESSION.exit_stack,
            )
        )
        _SESSION.runner.run(start_windows_vms_resource_monitoring(TASKS, END_TASKS))


# pylint: disable=unused-argument
def pytest_sessionfinish(session, exitstatus):
    if os.environ.get("NATLAB_SAVE_LOGS") is None or session.config.option.collectonly:
        return

    END_TASKS.set()

    if _SESSION.runner is not None:
        try:
            if _SESSION.exit_stack is not None:
                _SESSION.runner.run(_SESSION.exit_stack.aclose())
        finally:
            _SESSION.runner.close()

    asyncio.run(collect_logs(_SESSION.vm_marks))


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

        _SESSION.current_test_log_file = file_handler
    try:
        yield
    finally:
        pass
