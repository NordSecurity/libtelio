import asyncio
import hashlib
import pytest
import uuid
from contextlib import AsyncExitStack
from Pyro5.errors import CommunicationError  # type:ignore
from tests.config import UNIFFI_PATH_WINDOWS_VM
from tests.helpers import (
    SetupParameters,
    setup_api,
    setup_connections,
    setup_environment,
)
from tests.mesh_api import Node
from tests.telio import Client
from tests.utils.asyncio_util import run_async_context
from tests.utils.bindings import TelioAdapterType
from tests.utils.connection import Connection, ConnectionTag
from tests.utils.connection_util import new_connection_by_tag
from tests.utils.logger import log
from tests.utils.process import ProcessExecError
from tests.utils.router import IPStack
from typing import List


@pytest.mark.windows
@pytest.mark.parametrize("conn_tag", [ConnectionTag.VM_WINDOWS_1])
async def test_wg_adapter_cleanup(conn_tag: ConnectionTag):
    QUERY_CMD = [
        "reg",
        "query",
        r"HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}",
        "/s",
        "/f",
        "DeviceInstanceID",
    ]
    # Run libtelio and kill it dirty so it would leave hanging wg-nt adapter
    try:
        async with AsyncExitStack() as exit_stack:
            env = await exit_stack.enter_async_context(
                setup_environment(
                    exit_stack,
                    [
                        SetupParameters(
                            connection_tag=conn_tag,
                            adapter_type_override=TelioAdapterType.WINDOWS_NATIVE_TUN,
                        )
                    ],
                )
            )

            conn, *_ = [conn.connection for conn in env.connections]
            assert (
                "WireGuard"
                in (await conn.create_process(QUERY_CMD).execute()).get_stdout()
            )

            await conn.create_process(
                ["taskkill", "/T", "/F", "/IM", "python.exe"]
            ).execute()
    except (CommunicationError, ConnectionRefusedError, ProcessExecError) as e:
        log.warning("First libtelio failed with %s", e)

    # Check if libtelio left hanging wg-nt adapter, might now always happen, so we just leave test
    async with new_connection_by_tag(conn_tag) as conn:
        if (
            "WireGuard"
            not in (await conn.create_process(QUERY_CMD).execute()).get_stdout()
        ):
            return

    # Try to start libtelio and see if it properly cleans up orphaned wg-nt adapter and starts normaly
    async with AsyncExitStack() as exit_stack:
        env = await exit_stack.enter_async_context(
            setup_environment(
                exit_stack,
                [
                    SetupParameters(
                        connection_tag=conn_tag,
                        adapter_type_override=TelioAdapterType.WINDOWS_NATIVE_TUN,
                    )
                ],
            )
        )

        conn, *_ = [conn.connection for conn in env.connections]
        client, *_ = env.clients

        assert (
            "WireGuard" in (await conn.create_process(QUERY_CMD).execute()).get_stdout()
        )
        assert "Removed orphaned adapter" in client.get_stderr()


WG_NT_DLL_NAME = "wireguard.dll"
WG_NT_DLL_HIDDEN_NAME = f"{WG_NT_DLL_NAME}.hidden"
WG_NT_DLL = f"{UNIFFI_PATH_WINDOWS_VM}{WG_NT_DLL_NAME}"
WG_NT_DLL_HIDDEN = f"{UNIFFI_PATH_WINDOWS_VM}{WG_NT_DLL_HIDDEN_NAME}"

ADAPTER_GUID_POOL_SIZE = 8
PRIMARY_GUID_SLOT = 0
ADAPTER_CREATION_RETRY_LOG = "Retrying in"
STALE_ADAPTER_CONFIG_REMOVED_LOG = "Removed stale adapter config"
ORPHANED_ADAPTER_REMOVED_LOG = "Removed orphaned adapter"
KILL_LIBTELIO_REMOTE_CMD = ["taskkill", "/T", "/F", "/IM", "python.exe"]

NET_CLASS_KEY = r"HKLM\SYSTEM\CurrentControlSet\Control\Network\{4d36e972-e325-11ce-bfc1-08002be10318}"
SWD_WIREGUARD_KEY = r"HKLM\SYSTEM\CurrentControlSet\Enum\SWD\WireGuard"

PROXY_READY_POLL_INTERVAL_S = 0.5
FIRST_ADAPTER_CREATION_ATTEMPT_TIMEOUT_S = 60


def adapter_guid_for_slot(adapter_name: str, slot: int) -> str:
    hasher = hashlib.sha256(adapter_name.encode())
    if slot > PRIMARY_GUID_SLOT:
        hasher.update(b"\0")
        hasher.update(slot.to_bytes(8, "little"))
    guid = uuid.UUID(bytes_le=hasher.digest()[:16])
    return f"{{{str(guid).upper()}}}"


def adapter_device_key(adapter_name: str, slot: int) -> str:
    return f"{SWD_WIREGUARD_KEY}\\{adapter_guid_for_slot(adapter_name, slot)}"


def adapter_netcfg_key(adapter_name: str, slot: int) -> str:
    return f"{NET_CLASS_KEY}\\{adapter_guid_for_slot(adapter_name, slot)}"


async def reg_key_exists(conn: Connection, key: str) -> bool:
    try:
        await conn.create_process(["reg", "query", key], quiet=True).execute()
    except ProcessExecError:
        return False
    return True


async def used_guid_slots(conn: Connection, adapter_name: str) -> List[int]:
    return [
        slot
        for slot in range(ADAPTER_GUID_POOL_SIZE)
        if await reg_key_exists(conn, adapter_device_key(adapter_name, slot))
    ]


class HiddenWgNtDll:
    def __init__(self, conn: Connection) -> None:
        self._conn = conn
        self._hidden = False

    async def hide(self) -> None:
        log.info("Hiding %s as %s", WG_NT_DLL, WG_NT_DLL_HIDDEN_NAME)
        await self._conn.create_process(
            ["ren", WG_NT_DLL, WG_NT_DLL_HIDDEN_NAME]
        ).execute()
        self._hidden = True

    async def restore(self) -> None:
        if not self._hidden:
            return
        log.info("Restoring %s", WG_NT_DLL)
        await self._conn.create_process(
            ["ren", WG_NT_DLL_HIDDEN, WG_NT_DLL_NAME]
        ).execute()
        self._hidden = False


async def restore_dll_after_first_failed_attempt(
    client: Client, dll: HiddenWgNtDll
) -> None:
    async with asyncio.timeout(FIRST_ADAPTER_CREATION_ATTEMPT_TIMEOUT_S):
        while not client.is_proxy_ready():
            await asyncio.sleep(PROXY_READY_POLL_INTERVAL_S)
        log.info(
            "Libtelio proxy is ready, waiting for '%s' in telio log",
            ADAPTER_CREATION_RETRY_LOG,
        )
        await client.wait_for_log(ADAPTER_CREATION_RETRY_LOG)
    log.info("First adapter creation attempt failed as expected")
    await dll.restore()


def new_wg_nt_client(conn: Connection, node: Node, adapter_name: str) -> Client:
    client = Client(conn, node, TelioAdapterType.WINDOWS_NATIVE_TUN)
    client.get_router().set_interface_name(adapter_name)
    return client


def test_wg_adapter_guid_derivation_matches_libtelio() -> None:
    assert (
        adapter_guid_for_slot("NordLynx", PRIMARY_GUID_SLOT)
        == "{FC01FCD5-2B9D-2FD8-78D8-CB78B313E2B2}"
    )


@pytest.mark.windows
@pytest.mark.parametrize("conn_tag", [ConnectionTag.VM_WINDOWS_1])
async def test_wg_adapter_creation_retry(conn_tag: ConnectionTag) -> None:
    adapter_name = f"wgnt_retry_{uuid.uuid4().hex[:8]}"
    log.info("Using adapter name %s", adapter_name)
    for slot in range(ADAPTER_GUID_POOL_SIZE):
        log.info("GUID slot %d: %s", slot, adapter_guid_for_slot(adapter_name, slot))

    async with AsyncExitStack() as exit_stack:
        _, (node,) = setup_api([(False, IPStack.IPv4)])
        conn_manager, *_ = await setup_connections(exit_stack, [conn_tag])
        conn = conn_manager.connection

        dll = HiddenWgNtDll(conn)
        await dll.hide()
        exit_stack.push_async_callback(dll.restore)

        client = new_wg_nt_client(conn, node, adapter_name)
        restore_task = await exit_stack.enter_async_context(
            run_async_context(restore_dll_after_first_failed_attempt(client, dll))
        )
        log.info("Starting telio for the first time, with the dll hidden")
        used_slots: List[int] = []
        try:
            async with client.run():
                await restore_task
                log.info("Telio started, checking which GUID slot the adapter got")
                used_slots = await used_guid_slots(conn, adapter_name)
                log.info("GUID slots present in registry: %s", used_slots)
                log.info("Killing telio dirty, so the adapter is left behind")
                await conn.create_process(KILL_LIBTELIO_REMOTE_CMD).execute()
        except (CommunicationError, ConnectionRefusedError, ProcessExecError) as e:
            log.warning("Cleanup after killing libtelio failed with %s", e)

        assert len(used_slots) == 1, used_slots
        assert PRIMARY_GUID_SLOT not in used_slots
        (retry_slot,) = used_slots
        retry_device_key = adapter_device_key(adapter_name, retry_slot)
        retry_netcfg_key = adapter_netcfg_key(adapter_name, retry_slot)
        orphan_present = await reg_key_exists(conn, retry_device_key)
        leftover_present = await reg_key_exists(conn, retry_netcfg_key)
        log.info(
            "After the kill, GUID slot %d device present: %s, network config present: %s",
            retry_slot,
            orphan_present,
            leftover_present,
        )
        if not leftover_present:
            log.warning(
                "No network config left behind for GUID slot %d, cleanup has nothing to do",
                retry_slot,
            )

        log.info("Starting telio for the second time, with the dll restored")
        client = new_wg_nt_client(conn, node, adapter_name)
        async with client.run():
            log.info(
                "Telio started, checking that GUID slot %d was cleaned up", retry_slot
            )
            assert not await reg_key_exists(conn, retry_netcfg_key)
            used_slots = await used_guid_slots(conn, adapter_name)
            log.info("GUID slots present in registry: %s", used_slots)
            assert PRIMARY_GUID_SLOT in used_slots
            assert retry_slot not in used_slots
            telio_log = await client.get_log()
            if orphan_present:
                assert ORPHANED_ADAPTER_REMOVED_LOG in telio_log
            if leftover_present:
                assert STALE_ADAPTER_CONFIG_REMOVED_LOG in telio_log
            log.info("Stopping telio")
