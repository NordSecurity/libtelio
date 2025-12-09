import pytest
from contextlib import AsyncExitStack
from tests.helpers import SetupParameters, setup_environment
from tests.utils.bindings import TelioAdapterType
from tests.utils.connection import ConnectionTag
from tests.utils.connection_util import new_connection_raw
from tests.utils.testing import log_test_passed
from tests.utils.vm.windows_vm_util import get_network_interface_tunnel_keys


@pytest.mark.asyncio
@pytest.mark.windows
@pytest.mark.parametrize(
    "adapter_type, name",
    [
        (TelioAdapterType.WINDOWS_NATIVE_TUN, "WireGuard Tunnel"),
    ],
)
async def test_get_network_interface_tunnel_keys(adapter_type, name) -> None:
    async with AsyncExitStack() as exit_stack:
        connection = await exit_stack.enter_async_context(
            new_connection_raw(ConnectionTag.VM_WINDOWS_1)
        )
        assert [] == await get_network_interface_tunnel_keys(connection)
        _env = await exit_stack.enter_async_context(
            setup_environment(
                exit_stack,
                [
                    SetupParameters(
                        connection_tag=ConnectionTag.VM_WINDOWS_1,
                        adapter_type_override=adapter_type,
                    ),
                    SetupParameters(
                        connection_tag=ConnectionTag.DOCKER_CONE_CLIENT_2,
                        adapter_type_override=TelioAdapterType.LINUX_NATIVE_TUN,
                    ),
                ],
            )
        )

        # This function is used during test startup to remove interfaces
        # that might have managed to survive the end of the previous test.
        keys = await get_network_interface_tunnel_keys(connection)
        assert [
            "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Class\\{4d36e972-e325-11ce-bfc1-08002be10318}\\0003"
        ] == keys

        assert (
            name
            in (
                await connection.create_process(
                    ["reg", "query", keys[0]],
                    quiet=True,
                ).execute()
            ).get_stdout()
        )
        log_test_passed()
