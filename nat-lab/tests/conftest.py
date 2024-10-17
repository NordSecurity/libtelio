import asyncio
import os
import pytest
import subprocess
from helpers import SetupParameters
from interderp_cli import InterDerpClient
from itertools import combinations
from mesh_api import start_tcpdump, stop_tcpdump
from utils.bindings import TelioAdapterType
from utils.connection import DockerConnection
from utils.connection_util import ConnectionTag, LAN_ADDR_MAP, new_connection_raw
from utils.process import ProcessExecError
from utils.router import IPStack
from utils.vm import windows_vm_util, mac_vm_util

DERP_SERVER_1_ADDR = "http://10.0.10.1:8765"
DERP_SERVER_2_ADDR = "http://10.0.10.2:8765"
DERP_SERVER_3_ADDR = "http://10.0.10.3:8765"
DERP_SERVER_1_SECRET_KEY = "yBTYHj8yPlG9VtMYMwJSRHdzNdyAlVXGc6X2xJkjfHQ="
DERP_SERVER_2_SECRET_KEY = "2NgALOCSKJcDxwr8MtA+6lYbf7b98KSdAROGoUwZ1V0="

SETUP_CHECK_TIMEOUT_S = 30
SETUP_CHECK_RETRIES = 5


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

        if val.features.batching is not None:
            param_id += (
                f"-batch-{str(val.features.batching.direct_connection_threshold)}"
            )
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


async def setup_check_interderp():
    async with new_connection_raw(ConnectionTag.DOCKER_CONE_CLIENT_1) as connection:
        if not isinstance(connection, DockerConnection):
            raise Exception("Not docker connection")
        containers = [
            connection.container_name(),
            "nat-lab-derp-01-1",
            "nat-lab-derp-02-1",
            "nat-lab-derp-03-1",
        ]
        start_tcpdump(containers)
        try:
            for idx, (server1, server2) in enumerate(
                combinations(
                    [DERP_SERVER_1_ADDR, DERP_SERVER_2_ADDR, DERP_SERVER_3_ADDR], 2
                )
            ):
                derp_test = InterDerpClient(
                    connection,
                    server1,
                    server2,
                    DERP_SERVER_1_SECRET_KEY,
                    DERP_SERVER_2_SECRET_KEY,
                    idx,
                )
                await derp_test.execute()
                await derp_test.save_logs()
        finally:
            stop_tcpdump(containers)


SETUP_CHECKS = [
    (setup_check_interderp, SETUP_CHECK_TIMEOUT_S, SETUP_CHECK_RETRIES),
]


async def perform_setup_checks() -> bool:
    if "NATLAB_SKIP_SETUP_CHECKS" in os.environ:
        return True

    for target, timeout, retries in SETUP_CHECKS:
        while retries > 0:
            try:
                await asyncio.wait_for(asyncio.shield(target()), timeout)
                break
            except asyncio.TimeoutError:
                print(f"{target}() timeout, retrying...")
            except ProcessExecError as e:
                print(f"{target}() process exec error {e}, retrying...")
            retries -= 1
        else:
            return False

    return True


async def kill_natlab_processes():
    # Do not execute cleanup in non-CI environment,
    # because cleanup requires elevated privileges,
    # and it is rather inconvenient when every run
    # requires to enter sudo password
    # If someone really wants cleanup - one can set
    # ENABLE_NATLAB_PROCESS_CLEANUP envron variable
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
]


async def perform_pretest_cleanups():
    for cleanup in PRETEST_CLEANUPS:
        await cleanup()


async def _copy_vm_binaries(tag: ConnectionTag):
    is_ci = os.environ.get("CUSTOM_ENV_GITLAB_CI") is not None and os.environ.get(
        "CUSTOM_ENV_GITLAB_CI"
    )
    if tag in [ConnectionTag.WINDOWS_VM_1, ConnectionTag.WINDOWS_VM_2]:
        try:
            print(f"copying for {tag}")
            async with windows_vm_util.new_connection(
                LAN_ADDR_MAP[tag], copy_binaries=True
            ):
                pass
        except OSError as e:
            if is_ci:
                raise e
            print(e)
    elif tag is ConnectionTag.MAC_VM:
        try:
            async with mac_vm_util.new_connection(copy_binaries=True):
                pass
        except OSError as e:
            if is_ci:
                raise e
            print(e)


async def _copy_vm_binaries_if_needed(items):
    windows_bins_copied = False
    mac_bins_copied = False

    for item in items:
        for mark in item.own_markers:
            if mark.name == "windows" and not windows_bins_copied:
                await _copy_vm_binaries(ConnectionTag.WINDOWS_VM_1)
                await _copy_vm_binaries(ConnectionTag.WINDOWS_VM_2)
                windows_bins_copied = True
            elif mark.name == "mac" and not mac_bins_copied:
                await _copy_vm_binaries(ConnectionTag.MAC_VM)
                mac_bins_copied = True

            if windows_bins_copied and mac_bins_copied:
                return


def pytest_runtestloop(session):
    if not session.config.option.collectonly:
        asyncio.run(_copy_vm_binaries_if_needed(session.items))

        if not asyncio.run(perform_setup_checks()):
            pytest.exit("Setup checks failed, exiting ...")


def pytest_runtest_setup():
    asyncio.run(perform_pretest_cleanups())


# pylint: disable=unused-argument
def pytest_sessionfinish(session, exitstatus):
    if os.environ.get("NATLAB_SAVE_LOGS") is None:
        return

    if not session.config.option.collectonly:
        num_containers = 3

        for i in range(1, num_containers + 1):
            container_name = f"nat-lab-derp-{i:02d}-1"
            destination_path = f"logs/derp_{i:02d}_relay.log"

            docker_cp_command = f"docker cp {container_name}:/etc/nordderper/relay.log {destination_path}"

            try:
                subprocess.run(docker_cp_command, shell=True, check=True)
                print(f"Log file copied successfully from {container_name}")
            except subprocess.CalledProcessError:
                print(f"Error copying log file from {container_name}")
