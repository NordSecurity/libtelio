import asyncio
import logging
import os
import pytest
import shutil
import subprocess
from tests.helpers import SetupParameters
from tests.utils.bindings import TelioAdapterType
from tests.utils.connection import ConnectionTag, clear_ephemeral_setups_set
from tests.utils.logger import log
from tests.utils.router import IPStack
from tests.utils.testing import get_current_test_log_path


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


async def kill_natlab_processes():
    if (
        not "GITLAB_CI" in os.environ
        and not "ENABLE_NATLAB_PROCESS_CLEANUP" in os.environ
    ):
        return

    cleanup_script_path = os.path.join(
        os.path.dirname(__file__), "../bin/cleanup_natlab_processes"
    )
    subprocess.run(["sudo", cleanup_script_path]).check_returncode()


PRETEST_CLEANUPS = [
    kill_natlab_processes,
    clear_ephemeral_setups_set,
]


async def perform_pretest_cleanups():
    for cleanup in PRETEST_CLEANUPS:
        await cleanup()


def save_dmesg_from_host(suffix):
    try:
        result = subprocess.run(
            ["sudo", "dmesg", "-d", "-T"],
            capture_output=True,
            text=True,
            check=True,
        ).stdout
    except subprocess.CalledProcessError as e:
        log.error("Error executing dmesg: %s", e)
        return

    if result:
        with open(
            os.path.join("logs", f"dmesg-{suffix}.txt"), "w", encoding="utf-8"
        ) as f:
            f.write(result)


def save_audit_log_from_host(suffix):
    try:
        source_path = "/var/log/audit/audit.log"
        if os.path.exists(source_path):
            shutil.copy2(source_path, f"logs/audit_{suffix}.log")
        else:
            log.warning("The audit file %s", source_path)
    except Exception as e:  # pylint: disable=broad-exception-caught
        log.warning("An error occurred when processing audit log: %s", e)


# pylint: disable=unused-argument
async def collect_kernel_logs(items, suffix):
    log_dir = "logs"
    os.makedirs(log_dir, exist_ok=True)
    save_dmesg_from_host(suffix)
    save_audit_log_from_host(suffix)


def pytest_runtestloop(session):
    if not session.config.option.collectonly:
        if os.environ.get("NATLAB_SAVE_LOGS") is not None:
            asyncio.run(collect_kernel_logs(session.items, "before_tests"))


# pylint: disable=unused-argument
def pytest_runtest_setup(item):
    asyncio.run(perform_pretest_cleanups())


# pylint: disable=unused-argument
def pytest_sessionfinish(session, exitstatus):
    if os.environ.get("NATLAB_SAVE_LOGS") is None:
        return
    if not session.config.option.collectonly:
        asyncio.run(collect_kernel_logs(session.items, "after_tests"))


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

    try:
        yield
    finally:
        if file_handler:
            file_handler.flush()
            log.removeHandler(file_handler)
            file_handler.close()
        else:
            pass
