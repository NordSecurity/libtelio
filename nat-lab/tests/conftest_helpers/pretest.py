import base64
import os
import ssl
import subprocess
import urllib.error
import urllib.request
from contextlib import AsyncExitStack
from http import HTTPStatus
from tests.config import LAN_ADDR_MAP, CORE_API_IP, CORE_API_CREDENTIALS
from tests.utils.connection import ConnectionTag, clear_ephemeral_setups_set
from tests.utils.connection.ssh_connection import SshConnection
from tests.utils.connection_util import new_connection_raw, is_running
from tests.utils.logger import log, setup_log
from tests.utils.router import IPStack, new_router


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


async def reset_service_credentials_cache():
    ssl_context = ssl.create_default_context()
    ssl_context.check_hostname = False
    ssl_context.verify_mode = ssl.CERT_NONE
    credentials = (
        f"{CORE_API_CREDENTIALS['username']}:{CORE_API_CREDENTIALS['password']}"
    )
    encoded_credentials = base64.b64encode(credentials.encode()).decode()
    headers = {
        "Authorization": f"Basic {encoded_credentials}",
        "Content-Type": "application/json",
        "Content-Length": "0",
    }
    request = urllib.request.Request(
        f"https://{CORE_API_IP}/test/reset-credentials",
        data=b"",
        method="POST",
        headers=headers,
    )
    try:
        with urllib.request.urlopen(request, context=ssl_context) as response:
            if response.status == HTTPStatus.OK:
                setup_log.debug("Service credentials cache reset successfully")
            else:
                setup_log.warning(
                    "Failed to reset service credentials cache: HTTP %s",
                    response.status,
                )
    except urllib.error.HTTPError as e:
        setup_log.warning(
            "Failed to reset service credentials cache: HTTP %s - %s", e.code, e.reason
        )
        raise
    except Exception as e:  # pylint: disable=broad-exception-caught
        setup_log.warning("Error resetting service credentials cache: %s", e)
        raise


async def reset_upnpd_on_upnp_gateways():
    setup_log.info("Resetting miniupnpd on UPNP gateways..")
    async with AsyncExitStack() as exit_stack:
        for gw_tag in ConnectionTag:
            if "UPNP_GW" not in gw_tag.name:
                continue
            try:
                if not await is_running(gw_tag):
                    continue
                conn = await exit_stack.enter_async_context(new_connection_raw(gw_tag))
                router = new_router(conn, IPStack.IPv4v6)
                # Briefly stop and restart miniupnpd to purge any stale mappings
                async with router.reset_upnpd():
                    pass
                setup_log.debug("miniupnpd reset on %s", gw_tag.name)
            except Exception as e:  # pylint: disable=broad-exception-caught
                setup_log.warning("Failed to reset miniupnpd on %s: %s", gw_tag.name, e)


async def reset_machines_cache():
    ssl_context = ssl.create_default_context()
    ssl_context.check_hostname = False
    ssl_context.verify_mode = ssl.CERT_NONE
    credentials = (
        f"{CORE_API_CREDENTIALS['username']}:{CORE_API_CREDENTIALS['password']}"
    )
    encoded_credentials = base64.b64encode(credentials.encode()).decode()
    headers = {
        "Authorization": f"Basic {encoded_credentials}",
        "Content-Type": "application/json",
        "Content-Length": "0",
    }
    request = urllib.request.Request(
        f"https://{CORE_API_IP}/test/reset-machines",
        data=b"",
        method="POST",
        headers=headers,
    )
    try:
        with urllib.request.urlopen(
            request, context=ssl_context, timeout=5
        ) as response:
            if response.status == HTTPStatus.OK:
                log.debug("Machines cache reset successfully")
            else:
                log.warning(
                    "Failed to reset machines cache: HTTP %s",
                    response.status,
                )
    except urllib.error.HTTPError as e:
        log.debug("Failed to reset machines cache: HTTP %s - %s", e.code, e.reason)
    except Exception as e:  # pylint: disable=broad-exception-caught
        log.debug("Could not reset machines cache (server may not be running): %s", e)


PRETEST_CLEANUPS = [
    kill_natlab_processes,
    clear_ephemeral_setups_set,
    reset_service_credentials_cache,
    reset_machines_cache,
]


async def perform_pretest_cleanups():
    for cleanup in PRETEST_CLEANUPS:
        await cleanup()
    await reset_upnpd_on_upnp_gateways()


async def _copy_vm_binaries(tag: ConnectionTag):
    try:
        setup_log.info("Copying binaries for %s", tag)
        async with SshConnection.new_connection(
            LAN_ADDR_MAP[tag]["primary"], tag, copy_binaries=True
        ):
            pass
    except OSError as e:
        setup_log.error(e)
        raise e


async def copy_vm_binaries_if_needed(session_vm_marks: set[str]):
    if "windows" in session_vm_marks:
        await _copy_vm_binaries(ConnectionTag.VM_WINDOWS_1)
        try:
            await _copy_vm_binaries(ConnectionTag.VM_WINDOWS_2)
        except Exception as e:  # pylint: disable=broad-exception-caught
            setup_log.warning("[Ignored] Couldn't copy binary to VM_WINDOWS_2: %s", e)
    if "mac" in session_vm_marks:
        await _copy_vm_binaries(ConnectionTag.VM_MAC)
    if "openwrt" in session_vm_marks:
        await _copy_vm_binaries(ConnectionTag.VM_OPENWRT_GW_1)
