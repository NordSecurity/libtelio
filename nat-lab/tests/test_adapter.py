import asyncio
import pytest
import re
from enum import Enum
from tests import config
from tests.helpers import SetupParameters, Environment
from tests.utils import asyncio_util
from tests.utils.bindings import (
    ErrorEvent,
    ErrorCode,
    ErrorLevel,
    StartConfig,
    TelioAdapterType,
    default_features,
)
from tests.utils.connection import TargetOS, ConnectionTag
from tests.utils.connection_util import (
    generate_connection_tracker_config,
    ConnectionManager,
)
from tests.utils.process import ProcessExecError
from tests.utils.python import get_python_binary
from typing import Awaitable, Callable, List


class AdapterState(Enum):
    DOWN = (0,)
    UP = 1


MTU_POLL_ATTEMPTS = 20
MTU_POLL_INTERVAL_S = 0.5


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

    raise RuntimeError(f'Unexpected adapter state: "{output}"')


async def get_interface_mtu(client_conn, client, address_family: str) -> int:
    itf_name = client.get_router().get_interface_name()
    process = await client_conn.create_process([
        "powershell",
        "-Command",
        f'(Get-NetIPInterface -InterfaceAlias "{itf_name}"'
        f" -AddressFamily {address_family}).NlMtu",
    ]).execute()
    output = process.get_stdout().strip()

    if not output.isdigit():
        raise RuntimeError(
            f'Unexpected {address_family} MTU for "{itf_name}": "{output}"'
        )

    return int(output)


async def wait_for_interface_mtu(client_conn, client, expected_mtu: int) -> None:
    """
    Wait for both address families to report `expected_mtu`.

    The adapter sets each family separately and the interface watcher may
    re-apply the MTU on interface events, so the value is not readable
    immediately after the call that requested it.
    """
    expected = {"IPv4": expected_mtu, "IPv6": expected_mtu}
    actual: dict = {}

    for _ in range(MTU_POLL_ATTEMPTS):
        try:
            actual = {
                family: await get_interface_mtu(client_conn, client, family)
                for family in expected
            }
        except (ProcessExecError, RuntimeError):
            # The interface is missing or still settling after a restart
            actual = {}
        if actual == expected:
            break
        await asyncio.sleep(MTU_POLL_INTERVAL_S)

    assert actual == expected, f"Expected adapter MTUs {expected}, last read {actual}"


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
async def test_adapter_gone_event(
    alpha_setup_params: SetupParameters,  # pylint: disable=unused-argument
    env_mesh: Environment,
) -> None:
    env = env_mesh
    conn, *_ = [conn.connection for conn in env.connections]
    client, *_ = env.clients

    expected_event = ErrorEvent(
        level=ErrorLevel.CRITICAL,
        code=ErrorCode.UNKNOWN,
        msg="Interface gone",
    )

    async def delete_adapter() -> None:
        iface = client.get_router().get_interface_name()

        if conn.target_os == TargetOS.Linux:
            await conn.create_process(["ip", "link", "delete", iface]).execute()

        elif conn.target_os == TargetOS.Windows:
            try:
                await conn.create_process(
                    ["netsh", "interface", "set", "interface", iface, "disable"]
                ).execute()
            except ProcessExecError as e:
                if e.returncode != 1:
                    raise
        else:
            raise RuntimeError("unsupported os")

    async with asyncio_util.run_async_context(
        client.events.wait_for_event_error(expected_event)
    ) as event:
        await asyncio.gather(
            delete_adapter(),
            event,
        )

    client.allow_errors([
        "neptun::device.*Fatal read error on tun interface",
        "telio_wg::adapter::linux_native_wg.*LinuxNativeWg: \\[GET01\\] Unable to get interface from WireGuard. Make sure it exists and you have permissions to access it.",
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
    alpha_setup_params: SetupParameters,
    beta_setup_params: SetupParameters,
    setup_connections_factory: Callable[..., Awaitable[List[ConnectionManager]]],
    setup_mesh_nodes_factory: Callable[..., Awaitable[Environment]],
) -> None:
    """
    Windows-only test that verifies that the adapter service can be loaded, even if it was un-loaded before.
    """
    managers = await setup_connections_factory([alpha_setup_params.connection_tag])
    connection = managers[0].connection

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

    _ = await setup_mesh_nodes_factory([alpha_setup_params, beta_setup_params])


class TestAdapterStateForVpnAndDns:
    """Tests requiring single VPN with 1-node non-mesh (env)."""

    @pytest.fixture(name="vpn_tags")
    def _vpn_tags(self) -> list:
        return [ConnectionTag.DOCKER_VPN_1]

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
        self,
        alpha_setup_params: SetupParameters,
        env: Environment,
    ) -> None:
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
        await client_alpha.vpn.connect(server_ip, server_port, server_public_key)

        state = await get_interface_state(client_conn, client_alpha)
        assert state == AdapterState.UP

        await client_alpha.vpn.disconnect(server_public_key)

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
                        vpn_1_limits=(1, 2),
                    ),
                    is_meshnet=False,
                    features=default_features(enable_dynamic_wg_nt_control=True),
                ),
                marks=[pytest.mark.windows],
            ),
        ],
    )
    async def test_wg_nt_down_releases_listen_port(
        self,
        alpha_setup_params: SetupParameters,  # pylint: disable=unused-argument
        env: Environment,
    ) -> None:
        """
        LLT-6287: after a dynamic adapter Down the driver must not re-bind the
        stale listen port, so reconnecting works even if another process took it.
        """
        client_conn, *_ = [conn.connection for conn in env.connections]
        client_alpha, *_ = env.clients

        server_ip = str(config.WG_SERVER["ipv4"])
        server_port = int(config.WG_SERVER["port"])
        server_public_key = str(config.WG_SERVER["public_key"])

        await client_alpha.vpn.connect(server_ip, server_port, server_public_key)

        state = await get_interface_state(client_conn, client_alpha)
        assert state == AdapterState.UP

        ports = re.findall(r"listen_port: Some\((\d+)\)", await client_alpha.log.get())
        assert ports, "listen_port not found in libtelio log"
        listen_port = int(ports[-1])
        assert listen_port != 0

        await client_alpha.vpn.disconnect(server_public_key)

        state = await get_interface_state(client_conn, client_alpha)
        assert state == AdapterState.DOWN

        # TODO: LLT-5689 - rewrite with the NetCat wrapper once it supports Windows
        occupy_port_cmd = [
            get_python_binary(client_conn),
            "-c",
            "import socket, time; "
            "s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); "
            f"s.bind(('0.0.0.0', {listen_port})); "
            "print('BOUND', flush=True); "
            "time.sleep(600)",
        ]
        async with client_conn.create_process(occupy_port_cmd).run() as process:
            await process.wait_stdin_ready()
            while "BOUND" not in process.get_stdout():
                await asyncio.sleep(0.1)

            await client_alpha.vpn.connect(
                server_ip, server_port, server_public_key, timeout=40
            )

            state = await get_interface_state(client_conn, client_alpha)
            assert state == AdapterState.UP

    @pytest.mark.parametrize(
        "alpha_setup_params",
        [
            pytest.param(
                SetupParameters(
                    connection_tag=ConnectionTag.VM_WINDOWS_1,
                    adapter_type_override=TelioAdapterType.WINDOWS_NATIVE_TUN,
                    connection_tracker_config=generate_connection_tracker_config(
                        connection_tag=ConnectionTag.VM_WINDOWS_1,
                        derp_1_limits=(2, 2),
                        vpn_1_limits=(1, 1),
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
                        derp_1_limits=(2, 2),
                        vpn_1_limits=(1, 1),
                    ),
                    features=default_features(enable_dynamic_wg_nt_control=False),
                ),
                marks=[pytest.mark.windows],
            ),
        ],
    )
    async def test_adapter_state_for_meshnet_and_vpn(
        self,
        alpha_setup_params: SetupParameters,
        env: Environment,
    ) -> None:
        # Creates and enables meshnet without any nodes
        api = env.api
        client_conn, *_ = [conn.connection for conn in env.connections]
        client_alpha, *_ = env.clients

        expected_idle_state = (
            AdapterState.DOWN
            if alpha_setup_params.features.wireguard.enable_dynamic_wg_nt_control
            else AdapterState.UP
        )

        # If meshnet is enabled without any peers, adapter should still be Up
        state = await get_interface_state(client_conn, client_alpha)
        assert state == AdapterState.UP

        await client_alpha.set_mesh_off()
        state = await get_interface_state(client_conn, client_alpha)
        assert state == expected_idle_state

        # Add node to meshnet, adapter should go UP
        api.default_config_two_nodes()
        first_node_id = next(iter(api.nodes))
        mesh_config = api.get_meshnet_config(
            first_node_id, derp_servers=[config.DERP_PRIMARY]
        )
        await client_alpha.set_meshnet_config(mesh_config)
        state = await get_interface_state(client_conn, client_alpha)
        assert state == AdapterState.UP

        # Connect to VPN
        server_ip = config.WG_SERVER["ipv4"]
        server_port = config.WG_SERVER["port"]
        server_public_key = config.WG_SERVER["public_key"]
        assert (
            isinstance(server_ip, str)
            and isinstance(server_port, int)
            and isinstance(server_public_key, str)
        )
        await client_alpha.vpn.connect(server_ip, server_port, server_public_key)
        state = await get_interface_state(client_conn, client_alpha)
        assert state == AdapterState.UP

        await client_alpha.set_mesh_off()
        state = await get_interface_state(client_conn, client_alpha)
        assert state == AdapterState.UP

        await client_alpha.vpn.disconnect(server_public_key)
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
                    derp_1_limits=(3, 3),
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
                    derp_1_limits=(3, 3),
                ),
                features=default_features(enable_dynamic_wg_nt_control=False),
            ),
            marks=[pytest.mark.windows],
        ),
    ],
)
async def test_adapter_state_for_meshnet(
    alpha_setup_params: SetupParameters,
    env: Environment,
) -> None:
    # Creates and enables meshnet without any nodes
    api = env.api
    client_conn, *_ = [conn.connection for conn in env.connections]
    client_alpha, *_ = env.clients

    expected_idle_state = (
        AdapterState.DOWN
        if alpha_setup_params.features.wireguard.enable_dynamic_wg_nt_control
        else AdapterState.UP
    )

    # If meshnet is enabled without any peers, adapter should still be Up
    state = await get_interface_state(client_conn, client_alpha)
    assert state == AdapterState.UP

    await client_alpha.set_mesh_off()
    state = await get_interface_state(client_conn, client_alpha)
    assert state == expected_idle_state

    # Add node to meshnet, adapter should go UP
    api.default_config_two_nodes()
    first_node_id = next(iter(api.nodes))
    mesh_config = api.get_meshnet_config(
        first_node_id, derp_servers=[config.DERP_PRIMARY]
    )
    await client_alpha.set_meshnet_config(mesh_config)
    state = await get_interface_state(client_conn, client_alpha)
    assert state == AdapterState.UP

    await client_alpha.set_mesh_off()
    state = await get_interface_state(client_conn, client_alpha)
    assert state == expected_idle_state

    # Mesh with config, but without peers, adapter should be UP
    mesh_config.peers = None
    await client_alpha.set_meshnet_config(mesh_config)
    state = await get_interface_state(client_conn, client_alpha)
    assert state == AdapterState.UP

    await client_alpha.set_mesh_off()
    state = await get_interface_state(client_conn, client_alpha)
    assert state == expected_idle_state


@pytest.mark.windows
class TestAdapterMtu:
    """Setting the adapter MTU, supported on Windows only."""

    @pytest.fixture
    def alpha_setup_params(self) -> SetupParameters:
        return SetupParameters(
            connection_tag=ConnectionTag.VM_WINDOWS_1,
            adapter_type_override=TelioAdapterType.WINDOWS_NATIVE_TUN,
            is_meshnet=False,
            features=default_features(enable_dynamic_wg_nt_control=False),
        )

    async def test_starts_with_configured_mtu(self, env: Environment) -> None:
        client_conn, *_ = [conn.connection for conn in env.connections]
        client_alpha, *_ = env.clients
        expected_mtu = 1360

        await client_alpha.stop_device()
        await client_alpha.start_with_config(StartConfig(mtu=expected_mtu))

        await wait_for_interface_mtu(client_conn, client_alpha, expected_mtu)

    async def test_changes_mtu_at_runtime(self, env: Environment) -> None:
        client_conn, *_ = [conn.connection for conn in env.connections]
        client_alpha, *_ = env.clients
        expected_mtu = 1320

        for family in ("IPv4", "IPv6"):
            current_mtu = await get_interface_mtu(client_conn, client_alpha, family)
            assert current_mtu != expected_mtu

        await client_alpha.set_adapter_mtu(expected_mtu)

        await wait_for_interface_mtu(client_conn, client_alpha, expected_mtu)

    async def test_rejects_too_low_mtu(self, env: Environment) -> None:
        client_conn, *_ = [conn.connection for conn in env.connections]
        client_alpha, *_ = env.clients
        current_mtus = {
            family: await get_interface_mtu(client_conn, client_alpha, family)
            for family in ("IPv4", "IPv6")
        }

        with pytest.raises(RuntimeError, match="MtuTooLow"):
            await client_alpha.set_adapter_mtu(1279)

        for family, mtu in current_mtus.items():
            assert await get_interface_mtu(client_conn, client_alpha, family) == mtu


@pytest.mark.windows
class TestAdapterMtuWithDynamicWgNtControl:
    """A set MTU must survive the adapter going up and down."""

    @pytest.fixture(name="vpn_tags")
    def _vpn_tags(self) -> list:
        return [ConnectionTag.DOCKER_VPN_1]

    @pytest.fixture
    def alpha_setup_params(self) -> SetupParameters:
        return SetupParameters(
            connection_tag=ConnectionTag.VM_WINDOWS_1,
            adapter_type_override=TelioAdapterType.WINDOWS_NATIVE_TUN,
            connection_tracker_config=generate_connection_tracker_config(
                connection_tag=ConnectionTag.VM_WINDOWS_1,
                vpn_1_limits=(1, 1),
            ),
            is_meshnet=False,
            features=default_features(enable_dynamic_wg_nt_control=True),
        )

    async def test_mtu_survives_adapter_state_changes(self, env: Environment) -> None:
        client_conn, *_ = [conn.connection for conn in env.connections]
        client_alpha, *_ = env.clients
        expected_mtu = 1340

        state = await get_interface_state(client_conn, client_alpha)
        assert state == AdapterState.DOWN

        await client_alpha.set_adapter_mtu(expected_mtu)
        await wait_for_interface_mtu(client_conn, client_alpha, expected_mtu)

        server_ip = config.WG_SERVER["ipv4"]
        server_port = config.WG_SERVER["port"]
        server_public_key = config.WG_SERVER["public_key"]
        assert (
            isinstance(server_ip, str)
            and isinstance(server_port, int)
            and isinstance(server_public_key, str)
        )
        await client_alpha.vpn.connect(server_ip, server_port, server_public_key)

        state = await get_interface_state(client_conn, client_alpha)
        assert state == AdapterState.UP
        await wait_for_interface_mtu(client_conn, client_alpha, expected_mtu)

        await client_alpha.vpn.disconnect(server_public_key)

        state = await get_interface_state(client_conn, client_alpha)
        assert state == AdapterState.DOWN
        await wait_for_interface_mtu(client_conn, client_alpha, expected_mtu)


@pytest.mark.parametrize(
    "alpha_setup_params",
    [
        pytest.param(
            SetupParameters(
                connection_tag=ConnectionTag.DOCKER_CONE_CLIENT_1,
                adapter_type_override=TelioAdapterType.NEP_TUN,
                is_meshnet=False,
            ),
        ),
        pytest.param(
            SetupParameters(
                connection_tag=ConnectionTag.DOCKER_CONE_CLIENT_1,
                adapter_type_override=TelioAdapterType.LINUX_NATIVE_TUN,
                is_meshnet=False,
            ),
            marks=[pytest.mark.linux_native],
        ),
        pytest.param(
            SetupParameters(
                connection_tag=ConnectionTag.VM_MAC,
                adapter_type_override=TelioAdapterType.NEP_TUN,
                is_meshnet=False,
            ),
            marks=[pytest.mark.mac],
        ),
    ],
)
class TestAdapterMtuUnsupported:
    """Only the Windows native adapter supports setting the MTU."""

    async def test_rejects_mtu_at_runtime(
        self,
        alpha_setup_params: SetupParameters,  # pylint: disable=unused-argument
        env: Environment,
    ) -> None:
        client_alpha, *_ = env.clients

        with pytest.raises(RuntimeError, match="UnsupportedAdapter"):
            await client_alpha.set_adapter_mtu(1340)

    async def test_rejects_mtu_at_start(
        self,
        alpha_setup_params: SetupParameters,  # pylint: disable=unused-argument
        env: Environment,
    ) -> None:
        client_alpha, *_ = env.clients

        await client_alpha.stop_device()
        with pytest.raises(
            RuntimeError, match="MTU is only supported by the Windows native adapter"
        ):
            await client_alpha.start_with_config(StartConfig(mtu=1340))

        # Leave the device running for the test cleanup
        await client_alpha.start_with_config(StartConfig())
