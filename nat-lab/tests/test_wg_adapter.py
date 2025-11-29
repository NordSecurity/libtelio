import pytest
from contextlib import AsyncExitStack
from Pyro5.errors import CommunicationError  # type:ignore
from tests.helpers import SetupParameters, setup_environment
from tests.utils.bindings import TelioAdapterType
from tests.utils.connection import ConnectionTag
from tests.utils.connection_util import new_connection_by_tag
from tests.utils.logger import log
from tests.utils.process import ProcessExecError


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
    # Run libtelio and kill it dirty so it would leave hanging wintun adapter
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

    # Check if libtelio left hanging wintun adapter, might now always happen, so we just leave test
    async with new_connection_by_tag(conn_tag) as conn:
        if (
            "WireGuard"
            not in (await conn.create_process(QUERY_CMD).execute()).get_stdout()
        ):
            return

    # Try to start libtelio and see if it properly cleans up orphaned wintun adapter and starts normaly
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
