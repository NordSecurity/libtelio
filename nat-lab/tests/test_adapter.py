import pytest
from contextlib import AsyncExitStack
from enum import Enum
from tests import config
from tests.helpers import (
    SetupParameters,
    setup_environment,
    setup_mesh_nodes,
    setup_connections,
)
from tests.utils.bindings import (
    ErrorEvent,
    ErrorCode,
    ErrorLevel,
    TelioAdapterType,
    default_features,
)
from tests.utils.connection import TargetOS, ConnectionTag
from tests.utils.connection_util import generate_connection_tracker_config
from tests.utils.process import ProcessExecError


class AdapterState(Enum):
    DOWN = (0,)
    UP = 1


async def get_interface_state(client_conn, client):
    itf_name = client.get_router().get_interface_name()
    process = await client_conn.create_process([
        "powershell",
        "-Command",
        f'(Get-NetAdapter | Where-Object {{$_.Name -eq "{itf_name}"}}).Status',
    ]).execute()
    output = process.get_stdout()
    state_str = output.strip().lower()

    if state_str in ("disconnected", "down"):
        return AdapterState.DOWN
    if state_str in ("connected", "up"):
        return AdapterState.UP

    raise Exception(f'Unexpected adapter state: "{output}"')


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
                connection_tag=ConnectionTag.VM_WINDOWS_1,
                adapter_type_override=TelioAdapterType.WINDOWS_NATIVE_TUN,
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
            ErrorEvent(
                level=ErrorLevel.CRITICAL, code=ErrorCode.UNKNOWN, msg="Interface gone"
            )
        )

        client.allow_errors([
            "neptun::device.*Fatal read error on tun interface",
            "telio_wg::adapter::linux_native_wg.*LinuxNativeWg: \\[GET01\\] Unable to get interface from WireGuard. Make sure it exists and you have permissions to access it.",
            "wireguard_nt.*The system cannot find the file specified. (Code 0x00000002)",
        ])


@pytest.mark.parametrize(
    "alpha_setup_params",
    [
        pytest.param(
            SetupParameters(
                connection_tag=ConnectionTag.VM_WINDOWS_1,
                adapter_type_override=TelioAdapterType.WINDOWS_NATIVE_TUN,
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


@pytest.mark.parametrize(
    "alpha_setup_params",
    [
        pytest.param(
            SetupParameters(
                connection_tag=ConnectionTag.VM_WINDOWS_1,
                adapter_type_override=TelioAdapterType.WINDOWS_NATIVE_TUN,
                connection_tracker_config=generate_connection_tracker_config(
                    connection_tag=ConnectionTag.VM_WINDOWS_1,
                    vpn_1_limits=(1, 1),
                ),
                is_meshnet=False,
                features=default_features(enable_dynamic_wg_nt_control=True),
            ),
            marks=[pytest.mark.windows],
        ),
        pytest.param(
            SetupParameters(
                connection_tag=ConnectionTag.VM_WINDOWS_1,
                adapter_type_override=TelioAdapterType.WINDOWS_NATIVE_TUN,
                connection_tracker_config=generate_connection_tracker_config(
                    connection_tag=ConnectionTag.VM_WINDOWS_1,
                    vpn_1_limits=(1, 1),
                ),
                is_meshnet=False,
                features=default_features(enable_dynamic_wg_nt_control=False),
            ),
            marks=[pytest.mark.windows],
        ),
    ],
)
async def test_adapter_state_for_vpn_and_dns(
    alpha_setup_params: SetupParameters,
) -> None:
    async with AsyncExitStack() as exit_stack:
        env = await exit_stack.enter_async_context(
            setup_environment(exit_stack, [alpha_setup_params], prepare_vpn=True)
        )

        client_conn, *_ = [conn.connection for conn in env.connections]
        client_alpha, *_ = env.clients

        expected_idle_state = (
            AdapterState.DOWN
            if alpha_setup_params.features.wireguard.enable_dynamic_wg_nt_control
            else AdapterState.UP
        )

        actual_state = await get_interface_state(client_conn, client_alpha)
        assert actual_state == expected_idle_state

        await client_alpha.enable_magic_dns(["1.2.3.4"])

        state = await get_interface_state(client_conn, client_alpha)
        assert state == AdapterState.UP

        await client_alpha.disable_magic_dns()

        state = await get_interface_state(client_conn, client_alpha)
        assert state == expected_idle_state

        # attempt to connect to VPN
        server_ip = config.WG_SERVER["ipv4"]
        server_port = config.WG_SERVER["port"]
        server_public_key = config.WG_SERVER["public_key"]
        assert (
            isinstance(server_ip, str)
            and isinstance(server_port, int)
            and isinstance(server_public_key, str)
        )
        await client_alpha.connect_to_vpn(server_ip, server_port, server_public_key)

        state = await get_interface_state(client_conn, client_alpha)
        assert state == AdapterState.UP

        await client_alpha.disconnect_from_vpn(server_public_key)

        state = await get_interface_state(client_conn, client_alpha)
        assert state == expected_idle_state


@pytest.mark.parametrize(
    "alpha_setup_params",
    [
        pytest.param(
            SetupParameters(
                connection_tag=ConnectionTag.VM_WINDOWS_1,
                adapter_type_override=TelioAdapterType.WINDOWS_NATIVE_TUN,
                connection_tracker_config=generate_connection_tracker_config(
                    connection_tag=ConnectionTag.VM_WINDOWS_1,
                    derp_1_limits=(1, 1),
                ),
                features=default_features(enable_dynamic_wg_nt_control=True),
            ),
            marks=[pytest.mark.windows],
        ),
        pytest.param(
            SetupParameters(
                connection_tag=ConnectionTag.VM_WINDOWS_1,
                adapter_type_override=TelioAdapterType.WINDOWS_NATIVE_TUN,
                connection_tracker_config=generate_connection_tracker_config(
                    connection_tag=ConnectionTag.VM_WINDOWS_1,
                    derp_1_limits=(1, 1),
                ),
                features=default_features(enable_dynamic_wg_nt_control=False),
            ),
            marks=[pytest.mark.windows],
        ),
    ],
)
async def test_adapter_state_for_meshnet(alpha_setup_params: SetupParameters) -> None:
    async with AsyncExitStack() as exit_stack:
        # Creates and enables meshnet without any nodes
        env = await exit_stack.enter_async_context(
            setup_environment(exit_stack, [alpha_setup_params], prepare_vpn=True)
        )

        api = env.api
        client_conn, *_ = [conn.connection for conn in env.connections]
        client_alpha, *_ = env.clients

        expected_idle_state = (
            AdapterState.DOWN
            if alpha_setup_params.features.wireguard.enable_dynamic_wg_nt_control
            else AdapterState.UP
        )

        state = await get_interface_state(client_conn, client_alpha)
        assert state == expected_idle_state

        # Add node to meshnet
        api.default_config_two_nodes()
        first_node_id = next(iter(api.nodes))
        await client_alpha.set_meshnet_config(
            api.get_meshnet_config(first_node_id, derp_servers=[config.DERP_PRIMARY])
        )

        state = await get_interface_state(client_conn, client_alpha)
        assert state == AdapterState.UP

        await client_alpha.set_mesh_off()

        state = await get_interface_state(client_conn, client_alpha)
        assert state == expected_idle_state
