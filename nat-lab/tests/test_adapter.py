import pytest
from contextlib import AsyncExitStack
from helpers import SetupParameters, setup_mesh_nodes, setup_connections
from utils.bindings import ErrorEvent, ErrorCode, ErrorLevel, TelioAdapterType
from utils.connection import TargetOS, ConnectionTag
from utils.process import ProcessExecError


@pytest.mark.parametrize(
    "alpha_setup_params",
    [
        pytest.param(
            SetupParameters(
                connection_tag=ConnectionTag.DOCKER_CONE_CLIENT_1,
                adapter_type_override=TelioAdapterType.NEP_TUN,
            ),
        ),
        pytest.param(
            SetupParameters(
                connection_tag=ConnectionTag.DOCKER_CONE_CLIENT_1,
                adapter_type_override=TelioAdapterType.LINUX_NATIVE_TUN,
            ),
            marks=[pytest.mark.linux_native],
        ),
        pytest.param(
            SetupParameters(
                connection_tag=ConnectionTag.WINDOWS_VM_1,
                adapter_type_override=TelioAdapterType.WINDOWS_NATIVE_TUN,
            ),
            marks=[pytest.mark.windows],
        ),
        pytest.param(
            SetupParameters(
                connection_tag=ConnectionTag.WINDOWS_VM_1,
                adapter_type_override=TelioAdapterType.WIREGUARD_GO_TUN,
            ),
            marks=[pytest.mark.windows],
        ),
    ],
)
async def test_adapter_gone_event(alpha_setup_params: SetupParameters) -> None:
    async with AsyncExitStack() as exit_stack:
        env = await setup_mesh_nodes(exit_stack, [alpha_setup_params])
        conn, *_ = [conn.connection for conn in env.connections]
        client, *_ = env.clients

        if conn.target_os == TargetOS.Linux:
            await conn.create_process([
                "ip",
                "link",
                "delete",
                client.get_router().get_interface_name(),
            ]).execute()
        elif conn.target_os == TargetOS.Windows:
            try:
                await conn.create_process([
                    "netsh",
                    "interface",
                    "set",
                    "interface",
                    client.get_router().get_interface_name(),
                    "disable",
                ]).execute()
            except ProcessExecError as e:
                if e.returncode != 1:
                    raise
        else:
            raise RuntimeError("unsupported os")

        await client.wait_for_event_error(
            ErrorEvent(ErrorLevel.CRITICAL, ErrorCode.UNKNOWN, "Interface gone")
        )

        client.allow_errors([
            "neptun::device.*Fatal read error on tun interface",
            "telio_wg::adapter::wireguard_go.*Failed to read packet from TUN device: Driver indicated EOF while reading from tunnel",
            "telio_wg::adapter::linux_native_wg.*LinuxNativeWg: \\[GET01\\] Unable to get interface from WireGuard. Make sure it exists and you have permissions to access it.",
        ])


@pytest.mark.parametrize(
    "alpha_setup_params",
    [
        pytest.param(
            SetupParameters(
                connection_tag=ConnectionTag.WINDOWS_VM_1,
                adapter_type_override=TelioAdapterType.WINDOWS_NATIVE_TUN,
            ),
            marks=[pytest.mark.windows],
        ),
        pytest.param(
            SetupParameters(
                connection_tag=ConnectionTag.WINDOWS_VM_1,
                adapter_type_override=TelioAdapterType.WIREGUARD_GO_TUN,
            ),
            marks=[pytest.mark.windows],
        ),
    ],
)
@pytest.mark.parametrize(
    "beta_setup_params",
    [
        pytest.param(
            SetupParameters(
                connection_tag=ConnectionTag.DOCKER_CONE_CLIENT_1,
            )
        )
    ],
)
async def test_adapter_service_loading(
    alpha_setup_params: SetupParameters, beta_setup_params: SetupParameters
) -> None:
    """
    Windows-only test that verifies that the adapter service can be loaded, even if it was un-loaded before.
    """
    async with AsyncExitStack() as exit_stack:
        connection = (
            await setup_connections(exit_stack, [alpha_setup_params.connection_tag])
        )[0].connection

        try:
            await connection.create_process([
                "sc",
                "delete",
                "WireGuard",
            ]).execute()
        except ProcessExecError:
            pass

        try:
            await connection.create_process([
                "sc",
                "delete",
                "Wintun",
            ]).execute()
        except ProcessExecError:
            pass

    async with AsyncExitStack() as exit_stack:
        _ = await setup_mesh_nodes(exit_stack, [alpha_setup_params, beta_setup_params])
