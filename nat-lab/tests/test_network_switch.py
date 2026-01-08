import asyncio
import pytest
from contextlib import AsyncExitStack
from tests import config, timeouts
from tests.helpers import (
    setup_connections,
    setup_environment,
    setup_mesh_nodes,
    SetupParameters,
)
from tests.utils import stun
from tests.utils.asyncio_util import run_async_contexts
from tests.utils.bindings import (
    features_with_endpoint_providers,
    EndpointProvider,
    PathType,
    TelioAdapterType,
    NodeState,
    RelayState,
)
from tests.utils.connection import TargetOS, ConnectionTag
from tests.utils.network_switcher.network_switcher_windows import (
    Interface as WinInterface,
    NetworkSwitcherWindows,
    InterfaceState,
)
from tests.utils.ping import ping
from tests.utils.process import ProcessExecError
from tests.utils.testing import log_test_passed
from unittest.mock import Mock, AsyncMock, patch


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "connection_tag, primary_ip, secondary_ip",
    [
        pytest.param(
            ConnectionTag.DOCKER_SHARED_CLIENT_1,
            "10.0.254.1",
            "10.0.254.13",
        ),
        pytest.param(
            ConnectionTag.VM_WINDOWS_1,
            "10.0.254.15",
            "10.0.254.16",
            marks=pytest.mark.windows,
        ),
        pytest.param(
            ConnectionTag.VM_MAC,
            "10.0.254.19",
            "10.0.254.20",
            marks=pytest.mark.mac,
        ),
    ],
)
async def test_network_switcher(
    connection_tag: ConnectionTag, primary_ip: str, secondary_ip: str
) -> None:
    async with AsyncExitStack() as exit_stack:
        conn_mngr, *_ = await setup_connections(exit_stack, [connection_tag])
        assert await stun.get(conn_mngr.connection, config.STUN_SERVER) == primary_ip

        assert conn_mngr.network_switcher
        await conn_mngr.network_switcher.switch_to_secondary_network()
        assert await stun.get(conn_mngr.connection, config.STUN_SERVER) == secondary_ip

        log_test_passed()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "alpha_setup_params",
    [
        pytest.param(
            SetupParameters(
                connection_tag=ConnectionTag.DOCKER_SHARED_CLIENT_1,
                adapter_type_override=TelioAdapterType.NEP_TUN,
            ),
        ),
        pytest.param(
            SetupParameters(
                connection_tag=ConnectionTag.DOCKER_SHARED_CLIENT_1,
                adapter_type_override=TelioAdapterType.LINUX_NATIVE_TUN,
            ),
            marks=pytest.mark.linux_native,
        ),
        pytest.param(
            SetupParameters(
                connection_tag=ConnectionTag.VM_WINDOWS_1,
                adapter_type_override=TelioAdapterType.WINDOWS_NATIVE_TUN,
            ),
            marks=pytest.mark.windows,
        ),
        pytest.param(
            SetupParameters(
                connection_tag=ConnectionTag.VM_MAC,
                adapter_type_override=TelioAdapterType.NEP_TUN,
            ),
            marks=[
                pytest.mark.mac,
            ],
        ),
    ],
)
@pytest.mark.parametrize(
    "beta_setup_params",
    [
        pytest.param(
            SetupParameters(
                connection_tag=ConnectionTag.DOCKER_SYMMETRIC_CLIENT_1,
            )
        )
    ],
)
async def test_mesh_network_switch(
    alpha_setup_params: SetupParameters, beta_setup_params: SetupParameters
) -> None:
    async with AsyncExitStack() as exit_stack:
        env = await setup_mesh_nodes(
            exit_stack, [alpha_setup_params, beta_setup_params]
        )
        _, beta = env.nodes
        alpha_conn_mngr, *_ = env.connections
        client_alpha, _ = env.clients

        await ping(alpha_conn_mngr.connection, beta.ip_addresses[0])

        assert alpha_conn_mngr.network_switcher
        await alpha_conn_mngr.network_switcher.switch_to_secondary_network()
        await client_alpha.notify_network_change()

        await ping(alpha_conn_mngr.connection, beta.ip_addresses[0])

        log_test_passed()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "alpha_setup_params",
    [
        pytest.param(
            SetupParameters(
                connection_tag=ConnectionTag.DOCKER_SHARED_CLIENT_1,
                adapter_type_override=TelioAdapterType.NEP_TUN,
                is_meshnet=False,
            ),
        ),
        pytest.param(
            SetupParameters(
                connection_tag=ConnectionTag.DOCKER_SHARED_CLIENT_1,
                adapter_type_override=TelioAdapterType.LINUX_NATIVE_TUN,
                is_meshnet=False,
            ),
            marks=pytest.mark.linux_native,
        ),
        pytest.param(
            SetupParameters(
                connection_tag=ConnectionTag.VM_WINDOWS_1,
                adapter_type_override=TelioAdapterType.WINDOWS_NATIVE_TUN,
                is_meshnet=False,
            ),
            marks=[pytest.mark.windows],
        ),
        pytest.param(
            SetupParameters(
                connection_tag=ConnectionTag.VM_MAC,
                adapter_type_override=TelioAdapterType.NEP_TUN,
                is_meshnet=False,
            ),
            marks=[
                pytest.mark.mac,
            ],
        ),
    ],
)
async def test_vpn_network_switch(alpha_setup_params: SetupParameters) -> None:
    async with AsyncExitStack() as exit_stack:
        env = await exit_stack.enter_async_context(
            setup_environment(exit_stack, [alpha_setup_params], prepare_vpn=True)
        )
        client_alpha, *_ = env.clients
        alpha_conn_mngr, *_ = env.connections
        alpha_connection = alpha_conn_mngr.connection
        network_switcher = alpha_conn_mngr.network_switcher

        wg_server = config.WG_SERVER
        await client_alpha.connect_to_vpn(
            str(wg_server["ipv4"]), int(wg_server["port"]), str(wg_server["public_key"])
        )

        await ping(alpha_connection, config.PHOTO_ALBUM_IP)

        ip = await stun.get(alpha_connection, config.STUN_SERVER)
        assert ip == wg_server["ipv4"], f"wrong public IP when connected to VPN {ip}"
        assert network_switcher
        await network_switcher.switch_to_secondary_network()
        await client_alpha.notify_network_change()
        # This is really silly.. For some reason, adding a short sleep here allows the VPN
        # connection to be restored faster. The difference is almost 5 seconds. Without
        # the sleep, the test fails often due to timeouts. Its as if feeding data into
        # a connection, which is being restored, bogs down the connection and it takes
        # more time for the connection to be restored.
        if alpha_connection.target_os == TargetOS.Windows:
            await asyncio.sleep(1.0)

        await ping(alpha_connection, config.PHOTO_ALBUM_IP)

        ip = await stun.get(alpha_connection, config.STUN_SERVER)
        assert ip == wg_server["ipv4"], f"wrong public IP when connected to VPN {ip}"

        log_test_passed()


@pytest.mark.asyncio
@pytest.mark.timeout(timeouts.TEST_MESH_NETWORK_SWITCH_DIRECT_TIMEOUT)
@pytest.mark.parametrize(
    "alpha_setup_params",
    [
        pytest.param(
            SetupParameters(
                connection_tag=ConnectionTag.DOCKER_SHARED_CLIENT_1,
                adapter_type_override=TelioAdapterType.NEP_TUN,
                features=features_with_endpoint_providers([EndpointProvider.STUN]),
            ),
            marks=[],
        ),
        pytest.param(
            SetupParameters(
                connection_tag=ConnectionTag.DOCKER_SHARED_CLIENT_1,
                adapter_type_override=TelioAdapterType.LINUX_NATIVE_TUN,
                features=features_with_endpoint_providers([EndpointProvider.STUN]),
            ),
            marks=pytest.mark.linux_native,
        ),
        pytest.param(
            SetupParameters(
                connection_tag=ConnectionTag.VM_WINDOWS_1,
                adapter_type_override=TelioAdapterType.WINDOWS_NATIVE_TUN,
                features=features_with_endpoint_providers([EndpointProvider.STUN]),
            ),
            marks=[
                pytest.mark.windows,
            ],
        ),
        pytest.param(
            SetupParameters(
                connection_tag=ConnectionTag.VM_MAC,
                adapter_type_override=TelioAdapterType.NEP_TUN,
                features=features_with_endpoint_providers([EndpointProvider.STUN]),
            ),
            marks=[
                pytest.mark.mac,
            ],
        ),
    ],
)
@pytest.mark.parametrize(
    "beta_setup_params",
    [
        pytest.param(
            SetupParameters(
                connection_tag=ConnectionTag.DOCKER_CONE_CLIENT_2,
                adapter_type_override=TelioAdapterType.NEP_TUN,
                features=features_with_endpoint_providers([EndpointProvider.STUN]),
            )
        )
    ],
)
async def test_mesh_network_switch_direct(
    alpha_setup_params: SetupParameters, beta_setup_params: SetupParameters
) -> None:
    async with AsyncExitStack() as exit_stack:
        env = await setup_mesh_nodes(
            exit_stack, [alpha_setup_params, beta_setup_params]
        )
        alpha, beta = env.nodes
        (network_switcher, alpha_connection), *_ = [
            (conn.network_switcher, conn.connection) for conn in env.connections
        ]
        assert network_switcher
        alpha_client, beta_client = env.clients

        await ping(alpha_connection, beta.ip_addresses[0])

        derp_connected_future = alpha_client.wait_for_event_on_any_derp(
            [RelayState.CONNECTED]
        )

        # Beta doesn't change its endpoint, so WG roaming may be used by alpha node to restore
        # the connection, so no node event is logged in that case
        peers_connected_relay_future = beta_client.wait_for_event_peer(
            alpha.public_key, [NodeState.CONNECTED], [PathType.RELAY]
        )
        peers_connected_direct_future = beta_client.wait_for_event_peer(
            alpha.public_key, [NodeState.CONNECTED], [PathType.DIRECT]
        )
        async with run_async_contexts([
            derp_connected_future,
            peers_connected_relay_future,
            peers_connected_direct_future,
        ]) as (derp, relay, direct):
            await network_switcher.switch_to_secondary_network()
            await alpha_client.notify_network_change()
            await derp
            await relay
            await direct

        await ping(alpha_connection, beta.ip_addresses[0])

        # LLT-5532: To be cleaned up...
        alpha_client.allow_errors([
            "telio_traversal::endpoint_providers::stun.*Starting session failed.*A socket operation was attempted to an unreachable network"
        ])
        beta_client.allow_errors([
            "telio_traversal::endpoint_providers::stun.*Starting session failed.*A socket operation was attempted to an unreachable network"
        ])

        log_test_passed()


class TestInterfaceWindows:
    @pytest.mark.asyncio
    async def test_get_network_interfaces(self):
        mock_connection = Mock()
        mock_connection.tag = ConnectionTag.VM_WINDOWS_1

        show_interface_output = """Admin State    State          Type             Interface Name
-------------------------------------------------------------------------
Enabled        Connected      Dedicated        Ethernet
Enabled        Connected      Dedicated        Ethernet 2"""
        mock_show_interface_process = Mock()
        mock_show_interface_process.get_stdout.return_value = show_interface_output
        mock_show_interface_process.execute = AsyncMock(
            return_value=mock_show_interface_process
        )

        show_addresses_output = """Configuration for interface "Ethernet"
    DHCP enabled:                         No
    IP Address:                           192.168.151.54
    Subnet Prefix:                        192.168.151.0/24 (mask 255.255.255.0)
    Default Gateway:                      192.168.150.254
    Gateway Metric:                       256
    InterfaceMetric:                      15

Configuration for interface "Ethernet 2"
    DHCP enabled:                         No
    IP Address:                           192.168.150.54
    Subnet Prefix:                        192.168.150.0/24 (mask 255.255.255.0)
    InterfaceMetric:                      15

Configuration for interface "Loopback Pseudo-Interface 1"
    DHCP enabled:                         No
    IP Address:                           127.0.0.1
    Subnet Prefix:                        127.0.0.0/8 (mask 255.0.0.0)
    InterfaceMetric:                      75"""
        mock_show_address_process = Mock()
        mock_show_address_process.get_stdout.return_value = show_addresses_output
        mock_show_address_process.execute = AsyncMock(
            return_value=mock_show_address_process
        )

        mock_connection.create_process.side_effect = [
            mock_show_interface_process,
            mock_show_address_process,
            mock_show_interface_process,
            mock_show_interface_process,
            mock_show_interface_process,
        ]

        interfaces = await WinInterface.get_enabled_network_interfaces(mock_connection)

        assert len(interfaces) == 2

        ifc = WinInterface.find_interface_by_name(interfaces, "Ethernet")
        assert ifc, interfaces
        assert await ifc.get_state(mock_connection) is InterfaceState.Enabled
        assert ifc.ipv4 == config.LAN_ADDR_MAP[ConnectionTag.VM_WINDOWS_1]["secondary"]

        ifc = WinInterface.find_interface_by_name(interfaces, "Ethernet 2")
        assert ifc, interfaces
        assert await ifc.get_state(mock_connection) is InterfaceState.Enabled
        assert ifc.ipv4 == config.LAN_ADDR_MAP[ConnectionTag.VM_WINDOWS_1]["primary"]

        log_test_passed()

    @pytest.mark.asyncio
    async def test_delete_route_fails(self):
        mock_connection = Mock()
        mock_process = Mock()

        # interface doesn't exist -> success
        mock_error = ProcessExecError(
            1,
            "test",
            ["some", "cmd"],
            "The filename, directory name, or volume label syntax is incorrect",
            "",
        )
        mock_process.execute = AsyncMock(side_effect=mock_error)
        mock_connection.create_process.return_value = mock_process
        await WinInterface("Ethernet Instance 0", InterfaceState.Enabled).delete_route(
            mock_connection
        )

        # route doesn't exist -> success
        mock_error = ProcessExecError(1, "", [""], "Element not found", "")
        mock_process.execute = AsyncMock(side_effect=mock_error)
        mock_connection.create_process.return_value = mock_process
        await WinInterface("Ethernet Instance 0", InterfaceState.Enabled).delete_route(
            mock_connection
        )

        # command fails -> exception thrown
        mock_error = ProcessExecError(
            1, "", [""], "Failed to execute command error", "some stderr"
        )
        mock_process.execute = AsyncMock(side_effect=mock_error)
        mock_connection.create_process.return_value = mock_process
        with pytest.raises(ProcessExecError):
            await WinInterface(
                "Ethernet Instance 0", InterfaceState.Enabled
            ).delete_route(mock_connection)

        log_test_passed()

    @pytest.mark.asyncio
    async def test_interface_enable_with_slow_startup(self):
        mock_connection = Mock()
        mock_connection.tag = ConnectionTag.VM_WINDOWS_1
        mock_process = Mock()
        mock_process.execute = AsyncMock(return_value=mock_process)
        mock_connection.create_process.return_value = mock_process

        attempt_count = 0

        # pylint: disable-next=unused-argument
        async def mock_get_interfaces(*args, **kwargs):
            nonlocal attempt_count
            attempt_count += 1
            if attempt_count < 10:
                return []
            return [
                WinInterface(
                    "Ethernet Instance 0", InterfaceState.Enabled, "10.55.0.13"
                )
            ]

        with patch.object(
            WinInterface,
            "get_enabled_network_interfaces",
            side_effect=mock_get_interfaces,
        ):
            with patch("asyncio.sleep", new_callable=AsyncMock):
                ifc = WinInterface("Ethernet Instance 0", InterfaceState.Disabled)
                await ifc.enable(mock_connection)
                assert attempt_count == 10

        log_test_passed()


class TestNetworkSwitcherWindows:
    @pytest.mark.asyncio
    async def test_create_is_successful(self):
        mock_connection = Mock()
        mock_connection.tag = ConnectionTag.VM_WINDOWS_1
        test_interfaces = [
            WinInterface(
                "Primary",
                InterfaceState.Enabled,
                config.LAN_ADDR_MAP[ConnectionTag.VM_WINDOWS_1]["primary"],
            ),
            WinInterface(
                "Secondary",
                InterfaceState.Enabled,
                config.LAN_ADDR_MAP[ConnectionTag.VM_WINDOWS_1]["secondary"],
            ),
        ]

        with patch.object(
            WinInterface, "get_enabled_network_interfaces", return_value=test_interfaces
        ):
            nw_switcher = await NetworkSwitcherWindows.create(mock_connection)

            # pylint: disable=protected-access
            assert nw_switcher._primary_interface == test_interfaces[0]
            assert nw_switcher._secondary_interface == test_interfaces[1]

        log_test_passed()

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "interfaces",
        [
            pytest.param(
                [
                    WinInterface(
                        "Primary",
                        InterfaceState.Enabled,
                        config.LAN_ADDR_MAP[ConnectionTag.VM_WINDOWS_1]["primary"],
                    )
                ],
            ),
            pytest.param(
                [
                    WinInterface(
                        "Secondary",
                        InterfaceState.Enabled,
                        config.LAN_ADDR_MAP[ConnectionTag.VM_WINDOWS_1]["secondary"],
                    )
                ],
            ),
        ],
    )
    async def test_create_missing_interface(self, interfaces):
        mock_connection = Mock()
        mock_connection.tag = ConnectionTag.VM_WINDOWS_1
        strerr = rf"Couldn't find {'secondary' if interfaces[0].name == 'Primary' else 'primary'}"
        with patch.object(
            WinInterface, "get_enabled_network_interfaces", return_value=interfaces
        ):
            with pytest.raises(AssertionError, match=strerr):
                await NetworkSwitcherWindows.create(mock_connection)

        log_test_passed()

    @pytest.mark.asyncio
    async def test_create_with_disabled_interface_with_ip_assigned(self):
        mock_connection = Mock()
        mock_connection.tag = ConnectionTag.VM_WINDOWS_1

        show_interface_output = """Admin State    State          Type             Interface Name
-------------------------------------------------------------------------
Disabled       Connected      Dedicated        Ethernet
Enabled        Connected      Dedicated        Ethernet 2"""
        mock_show_interface_process = Mock()
        mock_show_interface_process.get_stdout.return_value = show_interface_output
        mock_show_interface_process.execute = AsyncMock(
            return_value=mock_show_interface_process
        )

        show_addresses_output = """Configuration for interface "Ethernet"
    DHCP enabled:                         No
    IP Address:                           192.168.151.54
    Subnet Prefix:                        192.168.151.0/24 (mask 255.255.255.0)
    Default Gateway:                      192.168.150.254
    Gateway Metric:                       256
    InterfaceMetric:                      15

Configuration for interface "Ethernet 2"
    DHCP enabled:                         No
    IP Address:                           192.168.150.54
    Subnet Prefix:                        192.168.150.0/24 (mask 255.255.255.0)
    InterfaceMetric:                      15

Configuration for interface "Loopback Pseudo-Interface 1"
    DHCP enabled:                         No
    IP Address:                           127.0.0.1
    Subnet Prefix:                        127.0.0.0/8 (mask 255.0.0.0)
    InterfaceMetric:                      75"""
        mock_show_address_process = Mock()
        mock_show_address_process.get_stdout.return_value = show_addresses_output
        mock_show_address_process.execute = AsyncMock(
            return_value=mock_show_address_process
        )
        mock_connection.create_process.side_effect = [
            mock_show_interface_process,
            mock_show_address_process,
        ]

        with pytest.raises(
            ValueError, match="Disabled interface with address assigned"
        ):
            await NetworkSwitcherWindows.create(mock_connection)

        log_test_passed()

    @pytest.mark.asyncio
    async def test_create_with_enabled_interface_without_ip_assigned(self):
        mock_connection = Mock()
        mock_connection.tag = ConnectionTag.VM_WINDOWS_1

        show_interface_output = """Admin State    State          Type             Interface Name
-------------------------------------------------------------------------
Enabled        Connected      Dedicated        Ethernet
Enabled        Connected      Dedicated        Ethernet 2"""
        mock_show_interface_process = Mock()
        mock_show_interface_process.get_stdout.return_value = show_interface_output
        mock_show_interface_process.execute = AsyncMock(
            return_value=mock_show_interface_process
        )

        show_addresses_output = """Configuration for interface "Ethernet"
    DHCP enabled:                         No
    IP Address:
    Subnet Prefix:                        192.168.151.0/24 (mask 255.255.255.0)
    Default Gateway:                      192.168.150.254
    Gateway Metric:                       256
    InterfaceMetric:                      15

Configuration for interface "Ethernet 2"
    DHCP enabled:                         No
    IP Address:                           192.168.150.54
    Subnet Prefix:                        192.168.150.0/24 (mask 255.255.255.0)
    InterfaceMetric:                      15

Configuration for interface "Loopback Pseudo-Interface 1"
    DHCP enabled:                         No
    IP Address:                           127.0.0.1
    Subnet Prefix:                        127.0.0.0/8 (mask 255.0.0.0)
    InterfaceMetric:                      75"""
        mock_show_address_process = Mock()
        mock_show_address_process.get_stdout.return_value = show_addresses_output
        mock_show_address_process.execute = AsyncMock(
            return_value=mock_show_address_process
        )
        mock_connection.create_process.side_effect = [
            mock_show_interface_process,
            mock_show_address_process,
        ]
        with pytest.raises(
            AssertionError, match=r"Couldn't find secondary VM interface"
        ):
            await NetworkSwitcherWindows.create(mock_connection)

        log_test_passed()

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "gateway",
        [
            pytest.param(config.GW_ADDR_MAP[ConnectionTag.VM_WINDOWS_1]["primary"]),
            pytest.param(config.GW_ADDR_MAP[ConnectionTag.VM_WINDOWS_1]["secondary"]),
        ],
    )
    async def test_switch_network(self, gateway):
        mock_primary = Mock(
            spec=WinInterface("Ethernet Instance 0", InterfaceState.Disabled)
        )
        mock_primary.delete_route = AsyncMock()

        mock_secondary = Mock(
            spec=WinInterface("Ethernet Instance 0 2", InterfaceState.Enabled)
        )
        mock_secondary.delete_route = AsyncMock()

        mock_process = Mock()
        mock_process.get_stdout.return_value = (
            f"0.0.0.0/0    {gateway}    Primary Interface"
        )
        mock_process.get_stderr.return_value = ""
        mock_process.execute = AsyncMock(return_value=mock_process)

        mock_connection = Mock()
        mock_connection.tag = ConnectionTag.VM_WINDOWS_1
        mock_connection.create_process.return_value = mock_process

        with patch(
            "tests.utils.network_switcher.network_switcher_windows.CommandGrepper"
        ) as mock_grepper:
            mock_grepper_instance = AsyncMock()
            mock_grepper_instance.check_exists = AsyncMock(return_value=True)
            mock_grepper.return_value = mock_grepper_instance

            nw_switcher = NetworkSwitcherWindows(
                mock_connection, mock_primary, mock_secondary
            )

            if gateway == config.GW_ADDR_MAP[ConnectionTag.VM_WINDOWS_1]["primary"]:
                await nw_switcher.switch_to_primary_network()
            else:
                await nw_switcher.switch_to_secondary_network()

            mock_primary.delete_route.assert_called_once()
            mock_secondary.delete_route.assert_called_once()

            mock_connection.create_process.assert_any_call([
                "netsh",
                "interface",
                "ipv4",
                "add",
                "route",
                "0.0.0.0/0",
                (
                    mock_primary.name
                    if gateway
                    == config.GW_ADDR_MAP[ConnectionTag.VM_WINDOWS_1]["primary"]
                    else mock_secondary.name
                ),
                f"nexthop={gateway}",
            ])

        log_test_passed()

    @pytest.mark.asyncio
    async def test_switch_network_failure(self):
        mock_primary = Mock(
            spec=WinInterface("Ethernet Instance 0", InterfaceState.Enabled)
        )
        mock_primary.delete_route = AsyncMock()

        mock_secondary = Mock(
            spec=WinInterface("Ethernet Instance 0 2", InterfaceState.Enabled)
        )
        mock_secondary.delete_route = AsyncMock()

        mock_process = Mock()
        mock_process.get_stdout.return_value = ""
        mock_process.get_stderr.return_value = ""
        mock_process.execute = AsyncMock(return_value=mock_process)

        mock_connection = Mock()
        mock_connection.tag = ConnectionTag.VM_WINDOWS_1
        mock_connection.create_process.return_value = mock_process

        mock_grepper_instance = Mock()
        mock_grepper_instance.check_exists = AsyncMock(return_value=False)

        # pylint: disable-next=unused-argument
        def mock_grepper_init(*args, **kwargs):
            return mock_grepper_instance

        with patch(
            "tests.utils.network_switcher.network_switcher_windows.CommandGrepper",
            side_effect=mock_grepper_init,
        ):
            nw_switcher = NetworkSwitcherWindows(
                mock_connection, mock_primary, mock_secondary
            )

            with pytest.raises(Exception, match="Failed to switch to primary network"):
                await nw_switcher.switch_to_primary_network()

            with pytest.raises(
                Exception, match="Failed to switch to secondary network"
            ):
                await nw_switcher.switch_to_secondary_network()

        log_test_passed()
