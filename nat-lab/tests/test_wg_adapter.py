import pytest
from contextlib import AsyncExitStack
from Pyro5.errors import CommunicationError  # type:ignore
from tests.config import WINDOWS_NETWORK_ADAPTER_REGISTRY_KEY
from tests.helpers import SetupParameters, setup_environment
from tests.timeouts import TEST_WG_ADAPTER_CLEANUP_TIMEOUT
from tests.utils.bindings import TelioAdapterType
from tests.utils.connection import ConnectionTag
from tests.utils.connection_util import new_connection_by_tag
from tests.utils.logger import log
from tests.utils.process import ProcessExecError

QUERY_CMD = [
    "reg",
    "query",
    WINDOWS_NETWORK_ADAPTER_REGISTRY_KEY,
    "/s",
    "/f",
    "DeviceInstanceID",
]

_NET_CLASS_KEY = r"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}"
_SW_DEVICE_CLASS_KEY = r"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{62f9c741-b25a-46ce-b54c-9bccce08b6f2}"


async def _log_adapter_class_info(conn) -> None:
    for key in [_NET_CLASS_KEY, _SW_DEVICE_CLASS_KEY]:
        try:
            result = await conn.create_process([
                "reg", "query", key, "/s", "/f", "DriverDesc",
            ]).execute()
            log.info("DriverDesc entries under %s:\n%s", key, result.get_stdout())
        except ProcessExecError:
            log.info("No DriverDesc entries found under %s", key)


@pytest.mark.windows
@pytest.mark.timeout(TEST_WG_ADAPTER_CLEANUP_TIMEOUT)
@pytest.mark.parametrize("iterations", [3])
@pytest.mark.parametrize("conn_tag", [ConnectionTag.VM_WINDOWS_1])
async def test_wg_adapter_cleanup_loop_clean_shutdown(
    conn_tag: ConnectionTag, iterations: int
):
    for i in range(iterations):
        log.info("Clean shutdown iteration %d", i)

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
            await _log_adapter_class_info(conn)
            assert (
                "WireGuard"
                in (await conn.create_process(QUERY_CMD).execute()).get_stdout()
            )

        # After clean exit, verify adapter was properly cleaned up
        async with new_connection_by_tag(conn_tag) as conn:
            assert (
                "WireGuard"
                not in (await conn.create_process(QUERY_CMD).execute()).get_stdout()
            )


@pytest.mark.windows
@pytest.mark.timeout(TEST_WG_ADAPTER_CLEANUP_TIMEOUT)
@pytest.mark.parametrize("iterations", [3])
@pytest.mark.parametrize("conn_tag", [ConnectionTag.VM_WINDOWS_1])
async def test_wg_adapter_cleanup_loop_dirty_shutdown(
    conn_tag: ConnectionTag, iterations: int
):
    for i in range(iterations):
        log.info("Dirty shutdown iteration %d", i)

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
            log.warning("Dirty shutdown iteration %d failed with %s", i, e)

        # Check if libtelio left hanging wg-nt adapter
        async with new_connection_by_tag(conn_tag) as conn:
            if (
                "WireGuard"
                not in (await conn.create_process(QUERY_CMD).execute()).get_stdout()
            ):
                log.info(
                    "No orphaned adapter found after dirty shutdown iteration %d", i
                )
                continue

        # Try to start libtelio and see if it properly cleans up orphaned wg-nt adapter
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
                "WireGuard"
                in (await conn.create_process(QUERY_CMD).execute()).get_stdout()
            )
            assert "Removed orphaned adapter" in client.get_stderr()
