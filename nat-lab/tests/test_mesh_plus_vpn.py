import asyncio
import config
import pytest
import telio
from contextlib import AsyncExitStack
from helpers import SetupParameters, setup_mesh_nodes
from mesh_api import API
from telio import AdapterType, State
from telio_features import TelioFeatures, Direct
from utils import testing, stun
from utils.connection_tracker import ConnectionLimits
from utils.connection_util import (
    generate_connection_tracker_config,
    ConnectionTag,
    new_connection_with_conn_tracker,
)
from utils.ping import Ping


# Marks in-tunnel stack only, exiting only through IPv4
@pytest.mark.asyncio
@pytest.mark.parametrize(
    "alpha_setup_params",
    [
        pytest.param(
            SetupParameters(
                connection_tag=ConnectionTag.DOCKER_CONE_CLIENT_1,
                adapter_type=telio.AdapterType.BoringTun,
                connection_tracker_config=generate_connection_tracker_config(
                    ConnectionTag.DOCKER_CONE_CLIENT_1,
                    derp_1_limits=ConnectionLimits(1, 1),
                    vpn_1_limits=ConnectionLimits(1, 1),
                ),
            )
        ),
        pytest.param(
            SetupParameters(
                connection_tag=ConnectionTag.DOCKER_CONE_CLIENT_1,
                adapter_type=telio.AdapterType.LinuxNativeWg,
                connection_tracker_config=generate_connection_tracker_config(
                    ConnectionTag.DOCKER_CONE_CLIENT_1,
                    derp_1_limits=ConnectionLimits(1, 1),
                    vpn_1_limits=ConnectionLimits(1, 1),
                ),
            ),
            marks=pytest.mark.linux_native,
        ),
        pytest.param(
            SetupParameters(
                connection_tag=ConnectionTag.WINDOWS_VM_1,
                adapter_type=telio.AdapterType.WindowsNativeWg,
                connection_tracker_config=generate_connection_tracker_config(
                    ConnectionTag.WINDOWS_VM_1,
                    derp_1_limits=ConnectionLimits(1, 1),
                    vpn_1_limits=ConnectionLimits(1, 1),
                ),
            ),
            marks=pytest.mark.windows,
        ),
        pytest.param(
            SetupParameters(
                connection_tag=ConnectionTag.WINDOWS_VM_1,
                adapter_type=telio.AdapterType.WireguardGo,
                connection_tracker_config=generate_connection_tracker_config(
                    ConnectionTag.WINDOWS_VM_1,
                    derp_1_limits=ConnectionLimits(1, 1),
                    vpn_1_limits=ConnectionLimits(1, 1),
                ),
            ),
            marks=[
                pytest.mark.windows,
            ],
        ),
        pytest.param(
            SetupParameters(
                connection_tag=ConnectionTag.MAC_VM,
                adapter_type=telio.AdapterType.BoringTun,
                connection_tracker_config=generate_connection_tracker_config(
                    ConnectionTag.MAC_VM,
                    derp_1_limits=ConnectionLimits(1, 1),
                    vpn_1_limits=ConnectionLimits(1, 1),
                ),
            ),
            marks=pytest.mark.mac,
        ),
    ],
)
@pytest.mark.parametrize(
    "beta_setup_params",
    [
        pytest.param(
            SetupParameters(
                connection_tag=ConnectionTag.DOCKER_CONE_CLIENT_2,
                connection_tracker_config=generate_connection_tracker_config(
                    ConnectionTag.DOCKER_CONE_CLIENT_2,
                    derp_1_limits=ConnectionLimits(1, 1),
                ),
            )
        )
    ],
)
async def test_mesh_plus_vpn_one_peer(
    alpha_setup_params: SetupParameters, beta_setup_params: SetupParameters
) -> None:
    async with AsyncExitStack() as exit_stack:
        env = await setup_mesh_nodes(
            exit_stack, [alpha_setup_params, beta_setup_params]
        )

        _, beta = env.nodes
        client_alpha, _ = env.clients
        connection_alpha, _ = [conn.connection for conn in env.connections]

        async with Ping(connection_alpha, beta.ip_addresses[0]).run() as ping:
            await ping.wait_for_next_ping()

        wg_server = config.WG_SERVER

        await client_alpha.connect_to_vpn(
            str(wg_server["ipv4"]), int(wg_server["port"]), str(wg_server["public_key"])
        )

        async with Ping(connection_alpha, beta.ip_addresses[0]).run() as ping:
            await ping.wait_for_next_ping()

        async with Ping(connection_alpha, config.STUN_SERVER).run() as ping:
            await ping.wait_for_next_ping()

        public_ip = await testing.wait_long(
            stun.get(connection_alpha, config.STUN_SERVER)
        )
        assert (
            public_ip == wg_server["ipv4"]
        ), f"wrong public IP when connected to VPN {public_ip}"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "alpha_setup_params",
    [
        pytest.param(
            SetupParameters(
                connection_tag=ConnectionTag.DOCKER_CONE_CLIENT_1,
                adapter_type=telio.AdapterType.BoringTun,
                connection_tracker_config=generate_connection_tracker_config(
                    ConnectionTag.DOCKER_CONE_CLIENT_1,
                    derp_1_limits=ConnectionLimits(1, 1),
                    vpn_1_limits=ConnectionLimits(1, 1),
                ),
            )
        ),
        pytest.param(
            SetupParameters(
                connection_tag=ConnectionTag.DOCKER_CONE_CLIENT_1,
                adapter_type=telio.AdapterType.LinuxNativeWg,
                connection_tracker_config=generate_connection_tracker_config(
                    ConnectionTag.DOCKER_CONE_CLIENT_1,
                    derp_1_limits=ConnectionLimits(1, 1),
                    vpn_1_limits=ConnectionLimits(1, 1),
                ),
            ),
            marks=pytest.mark.linux_native,
        ),
        pytest.param(
            SetupParameters(
                connection_tag=ConnectionTag.WINDOWS_VM_1,
                adapter_type=telio.AdapterType.WindowsNativeWg,
                connection_tracker_config=generate_connection_tracker_config(
                    ConnectionTag.WINDOWS_VM_1,
                    derp_1_limits=ConnectionLimits(1, 1),
                    vpn_1_limits=ConnectionLimits(1, 1),
                ),
            ),
            marks=pytest.mark.windows,
        ),
        pytest.param(
            SetupParameters(
                connection_tag=ConnectionTag.WINDOWS_VM_1,
                adapter_type=telio.AdapterType.WireguardGo,
                connection_tracker_config=generate_connection_tracker_config(
                    ConnectionTag.WINDOWS_VM_1,
                    derp_1_limits=ConnectionLimits(1, 1),
                    vpn_1_limits=ConnectionLimits(1, 1),
                ),
            ),
            marks=[
                pytest.mark.windows,
            ],
        ),
        pytest.param(
            SetupParameters(
                connection_tag=ConnectionTag.MAC_VM,
                adapter_type=telio.AdapterType.BoringTun,
                connection_tracker_config=generate_connection_tracker_config(
                    ConnectionTag.MAC_VM,
                    derp_1_limits=ConnectionLimits(1, 1),
                    vpn_1_limits=ConnectionLimits(1, 1),
                ),
            ),
            marks=pytest.mark.mac,
        ),
    ],
)
@pytest.mark.parametrize(
    "beta_setup_params",
    [
        pytest.param(
            SetupParameters(
                connection_tag=ConnectionTag.DOCKER_CONE_CLIENT_2,
                connection_tracker_config=generate_connection_tracker_config(
                    ConnectionTag.DOCKER_CONE_CLIENT_2,
                    derp_1_limits=ConnectionLimits(1, 1),
                    vpn_1_limits=ConnectionLimits(1, 1),
                ),
            )
        )
    ],
)
async def test_mesh_plus_vpn_both_peers(
    alpha_setup_params: SetupParameters, beta_setup_params: SetupParameters
) -> None:
    async with AsyncExitStack() as exit_stack:
        env = await setup_mesh_nodes(
            exit_stack, [alpha_setup_params, beta_setup_params]
        )

        alpha, beta = env.nodes
        client_alpha, client_beta = env.clients
        connection_alpha, connection_beta = [
            conn.connection for conn in env.connections
        ]

        async with Ping(connection_alpha, beta.ip_addresses[0]).run() as ping:
            await ping.wait_for_next_ping()

        wg_server = config.WG_SERVER

        await asyncio.gather(
            client_alpha.connect_to_vpn(
                str(wg_server["ipv4"]),
                int(wg_server["port"]),
                str(wg_server["public_key"]),
            ),
            client_beta.connect_to_vpn(
                str(wg_server["ipv4"]),
                int(wg_server["port"]),
                str(wg_server["public_key"]),
            ),
        )

        async with Ping(connection_alpha, beta.ip_addresses[0]).run() as ping:
            await ping.wait_for_next_ping()
        async with Ping(connection_alpha, config.STUN_SERVER).run() as ping:
            await ping.wait_for_next_ping()

        async with Ping(connection_beta, alpha.ip_addresses[0]).run() as ping:
            await ping.wait_for_next_ping()
        async with Ping(connection_beta, config.STUN_SERVER).run() as ping:
            await ping.wait_for_next_ping()

        for connection in [connection_alpha, connection_beta]:
            public_ip = await testing.wait_long(
                stun.get(connection, config.STUN_SERVER)
            )
            assert (
                public_ip == wg_server["ipv4"]
            ), f"wrong public IP when connected to VPN {public_ip}"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "alpha_connection_tag,adapter_type,public_ip",
    [
        pytest.param(
            ConnectionTag.DOCKER_CONE_CLIENT_1,
            AdapterType.BoringTun,
            "10.0.254.1",
        ),
        pytest.param(
            ConnectionTag.DOCKER_CONE_CLIENT_1,
            AdapterType.LinuxNativeWg,
            "10.0.254.1",
            marks=pytest.mark.linux_native,
        ),
        pytest.param(
            ConnectionTag.WINDOWS_VM_1,
            AdapterType.WindowsNativeWg,
            "10.0.254.7",
            marks=pytest.mark.windows,
        ),
        pytest.param(
            ConnectionTag.WINDOWS_VM_1,
            AdapterType.WireguardGo,
            "10.0.254.7",
            marks=pytest.mark.windows,
        ),
        pytest.param(
            ConnectionTag.MAC_VM,
            AdapterType.Default,
            "10.0.254.7",
            marks=pytest.mark.mac,
        ),
    ],
)
async def test_vpn_plus_mesh(
    alpha_connection_tag: ConnectionTag, adapter_type: AdapterType, public_ip: str
) -> None:
    async with AsyncExitStack() as exit_stack:
        api = API()

        (alpha, beta) = api.default_config_two_nodes()
        (connection_alpha, alpha_conn_tracker) = await exit_stack.enter_async_context(
            new_connection_with_conn_tracker(
                alpha_connection_tag,
                generate_connection_tracker_config(
                    alpha_connection_tag,
                    derp_1_limits=ConnectionLimits(1, 1),
                    vpn_1_limits=ConnectionLimits(1, 1),
                    stun_limits=ConnectionLimits(1, 1),
                ),
            )
        )
        (connection_beta, beta_conn_tracker) = await exit_stack.enter_async_context(
            new_connection_with_conn_tracker(
                ConnectionTag.DOCKER_CONE_CLIENT_2,
                generate_connection_tracker_config(
                    ConnectionTag.DOCKER_CONE_CLIENT_2,
                    derp_1_limits=ConnectionLimits(1, 1),
                ),
            )
        )

        ip = await testing.wait_long(stun.get(connection_alpha, config.STUN_SERVER))
        assert ip == public_ip, f"wrong public IP before connecting to VPN {ip}"

        client_alpha = await exit_stack.enter_async_context(
            telio.Client(connection_alpha, alpha, adapter_type).run()
        )

        wg_server = config.WG_SERVER

        await client_alpha.connect_to_vpn(
            str(wg_server["ipv4"]), int(wg_server["port"]), str(wg_server["public_key"])
        )

        async with Ping(connection_alpha, config.PHOTO_ALBUM_IP).run() as ping:
            await ping.wait_for_next_ping()

        ip = await testing.wait_long(stun.get(connection_alpha, config.STUN_SERVER))
        assert ip == wg_server["ipv4"], f"wrong public IP when connected to VPN {ip}"

        await client_alpha.set_meshmap(api.get_meshmap(alpha.id))

        client_beta = await exit_stack.enter_async_context(
            telio.Client(connection_beta, beta).run(api.get_meshmap(beta.id))
        )

        await asyncio.gather(
            client_alpha.wait_for_state_on_any_derp([State.Connected]),
            client_beta.wait_for_state_on_any_derp([State.Connected]),
        )
        await asyncio.gather(
            client_alpha.wait_for_state_peer(beta.public_key, [State.Connected]),
            client_beta.wait_for_state_peer(alpha.public_key, [State.Connected]),
        )

        async with Ping(connection_alpha, beta.ip_addresses[0]).run() as ping:
            await ping.wait_for_next_ping()

        # Testing if the VPN node is not cleared after disabling meshnet. See LLT-4266 for more details.
        await client_alpha.set_mesh_off()
        await client_alpha.wait_for_event_peer(
            beta.public_key, [State.Disconnected], list(telio.PathType)
        )
        ip = await testing.wait_long(stun.get(connection_alpha, config.STUN_SERVER))
        assert ip == wg_server["ipv4"], f"wrong public IP when connected to VPN {ip}"

        assert alpha_conn_tracker.get_out_of_limits() is None
        assert beta_conn_tracker.get_out_of_limits() is None


@pytest.mark.asyncio
@pytest.mark.timeout(150)
@pytest.mark.parametrize(
    "alpha_setup_params",
    [
        pytest.param(
            SetupParameters(
                connection_tag=ConnectionTag.DOCKER_CONE_CLIENT_1,
                adapter_type=telio.AdapterType.BoringTun,
                connection_tracker_config=generate_connection_tracker_config(
                    ConnectionTag.DOCKER_CONE_CLIENT_1,
                    derp_1_limits=ConnectionLimits(1, 1),
                    vpn_1_limits=ConnectionLimits(1, 1),
                ),
                features=TelioFeatures(direct=Direct(providers=["local", "stun"])),
            ),
        ),
        pytest.param(
            SetupParameters(
                connection_tag=ConnectionTag.DOCKER_CONE_CLIENT_1,
                adapter_type=telio.AdapterType.LinuxNativeWg,
                connection_tracker_config=generate_connection_tracker_config(
                    ConnectionTag.DOCKER_CONE_CLIENT_1,
                    derp_1_limits=ConnectionLimits(1, 1),
                    vpn_1_limits=ConnectionLimits(1, 1),
                ),
                features=TelioFeatures(direct=Direct(providers=["local", "stun"])),
            ),
            marks=[
                pytest.mark.linux_native,
            ],
        ),
        pytest.param(
            SetupParameters(
                connection_tag=ConnectionTag.WINDOWS_VM_1,
                adapter_type=telio.AdapterType.WindowsNativeWg,
                connection_tracker_config=generate_connection_tracker_config(
                    ConnectionTag.WINDOWS_VM_1,
                    derp_1_limits=ConnectionLimits(1, 1),
                    vpn_1_limits=ConnectionLimits(1, 1),
                ),
                features=TelioFeatures(direct=Direct(providers=["local", "stun"])),
            ),
            marks=[
                pytest.mark.windows,
            ],
        ),
        pytest.param(
            SetupParameters(
                connection_tag=ConnectionTag.WINDOWS_VM_1,
                adapter_type=telio.AdapterType.WireguardGo,
                connection_tracker_config=generate_connection_tracker_config(
                    ConnectionTag.WINDOWS_VM_1,
                    derp_1_limits=ConnectionLimits(1, 1),
                    vpn_1_limits=ConnectionLimits(1, 1),
                ),
                features=TelioFeatures(direct=Direct(providers=["local", "stun"])),
            ),
            marks=[
                pytest.mark.windows,
            ],
        ),
        pytest.param(
            SetupParameters(
                connection_tag=ConnectionTag.MAC_VM,
                adapter_type=telio.AdapterType.BoringTun,
                connection_tracker_config=generate_connection_tracker_config(
                    ConnectionTag.MAC_VM,
                    derp_1_limits=ConnectionLimits(1, 1),
                    vpn_1_limits=ConnectionLimits(1, 1),
                ),
                features=TelioFeatures(direct=Direct(providers=["local", "stun"])),
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
                connection_tracker_config=generate_connection_tracker_config(
                    ConnectionTag.DOCKER_CONE_CLIENT_2,
                    derp_1_limits=ConnectionLimits(1, 1),
                    vpn_1_limits=ConnectionLimits(1, 1),
                ),
                features=TelioFeatures(direct=Direct(providers=["local", "stun"])),
            )
        )
    ],
)
async def test_vpn_plus_mesh_over_direct(
    alpha_setup_params: SetupParameters, beta_setup_params: SetupParameters
) -> None:
    async with AsyncExitStack() as exit_stack:
        env = await setup_mesh_nodes(
            exit_stack, [alpha_setup_params, beta_setup_params]
        )

        alpha, beta = env.nodes
        client_alpha, client_beta = env.clients
        connection_alpha, connection_beta = [
            conn.connection for conn in env.connections
        ]

        async with Ping(connection_alpha, beta.ip_addresses[0]).run() as ping:
            await ping.wait_for_next_ping(60)
        async with Ping(connection_beta, alpha.ip_addresses[0]).run() as ping:
            await ping.wait_for_next_ping(60)

        wg_server = config.WG_SERVER

        await asyncio.gather(
            client_alpha.connect_to_vpn(
                str(wg_server["ipv4"]),
                int(wg_server["port"]),
                str(wg_server["public_key"]),
            ),
            client_beta.connect_to_vpn(
                str(wg_server["ipv4"]),
                int(wg_server["port"]),
                str(wg_server["public_key"]),
            ),
        )

        async with Ping(connection_alpha, beta.ip_addresses[0]).run() as ping:
            # TODO: change waiting time to `wait_long` after issue LLT-3879 is fixed
            await testing.wait_defined(ping.wait_for_next_ping(), 60)
        async with Ping(connection_alpha, config.STUN_SERVER).run() as ping:
            await ping.wait_for_next_ping()

        async with Ping(connection_beta, alpha.ip_addresses[0]).run() as ping:
            # TODO: change waiting time to `wait_long` after issue LLT-3879 is fixed
            await testing.wait_defined(ping.wait_for_next_ping(), 60)
        async with Ping(connection_beta, config.STUN_SERVER).run() as ping:
            await ping.wait_for_next_ping()

        for connection in [connection_alpha, connection_beta]:
            public_ip = await testing.wait_long(
                stun.get(connection, config.STUN_SERVER)
            )
            assert (
                public_ip == wg_server["ipv4"]
            ), f"wrong public IP when connected to VPN {public_ip}"


@pytest.mark.asyncio
@pytest.mark.timeout(150)
@pytest.mark.parametrize(
    "alpha_setup_params",
    [
        pytest.param(
            SetupParameters(
                connection_tag=ConnectionTag.DOCKER_CONE_CLIENT_1,
                adapter_type=telio.AdapterType.BoringTun,
                connection_tracker_config=generate_connection_tracker_config(
                    ConnectionTag.DOCKER_CONE_CLIENT_1,
                    derp_1_limits=ConnectionLimits(1, 1),
                    vpn_1_limits=ConnectionLimits(1, 1),
                ),
                features=TelioFeatures(direct=Direct(providers=["local", "stun"])),
            )
        ),
        pytest.param(
            SetupParameters(
                connection_tag=ConnectionTag.DOCKER_CONE_CLIENT_1,
                adapter_type=telio.AdapterType.LinuxNativeWg,
                connection_tracker_config=generate_connection_tracker_config(
                    ConnectionTag.DOCKER_CONE_CLIENT_1,
                    derp_1_limits=ConnectionLimits(1, 1),
                    vpn_1_limits=ConnectionLimits(1, 1),
                ),
                features=TelioFeatures(direct=Direct(providers=["local", "stun"])),
            ),
            marks=pytest.mark.linux_native,
        ),
        pytest.param(
            SetupParameters(
                connection_tag=ConnectionTag.WINDOWS_VM_1,
                adapter_type=telio.AdapterType.WindowsNativeWg,
                connection_tracker_config=generate_connection_tracker_config(
                    ConnectionTag.WINDOWS_VM_1,
                    derp_1_limits=ConnectionLimits(1, 1),
                    vpn_1_limits=ConnectionLimits(1, 1),
                ),
                features=TelioFeatures(direct=Direct(providers=["local", "stun"])),
            ),
            marks=pytest.mark.windows,
        ),
        pytest.param(
            SetupParameters(
                connection_tag=ConnectionTag.WINDOWS_VM_1,
                adapter_type=telio.AdapterType.WireguardGo,
                connection_tracker_config=generate_connection_tracker_config(
                    ConnectionTag.WINDOWS_VM_1,
                    derp_1_limits=ConnectionLimits(1, 1),
                    vpn_1_limits=ConnectionLimits(1, 1),
                ),
                features=TelioFeatures(direct=Direct(providers=["local", "stun"])),
            ),
            marks=[
                pytest.mark.windows,
            ],
        ),
        pytest.param(
            SetupParameters(
                connection_tag=ConnectionTag.MAC_VM,
                adapter_type=telio.AdapterType.BoringTun,
                connection_tracker_config=generate_connection_tracker_config(
                    ConnectionTag.MAC_VM,
                    derp_1_limits=ConnectionLimits(1, 1),
                    vpn_1_limits=ConnectionLimits(1, 1),
                ),
                features=TelioFeatures(direct=Direct(providers=["local", "stun"])),
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
                connection_tracker_config=generate_connection_tracker_config(
                    ConnectionTag.DOCKER_CONE_CLIENT_2,
                    derp_1_limits=ConnectionLimits(1, 1),
                    vpn_1_limits=ConnectionLimits(1, 1),
                ),
                features=TelioFeatures(direct=Direct(providers=["local", "stun"])),
            )
        )
    ],
)
@pytest.mark.parametrize(
    "gamma_setup_params",
    [
        pytest.param(
            SetupParameters(
                connection_tag=ConnectionTag.DOCKER_SYMMETRIC_CLIENT_1,
                connection_tracker_config=generate_connection_tracker_config(
                    ConnectionTag.DOCKER_SYMMETRIC_CLIENT_1,
                    derp_1_limits=ConnectionLimits(1, 1),
                    vpn_1_limits=ConnectionLimits(1, 1),
                ),
            )
        )
    ],
)
async def test_vpn_plus_mesh_over_different_connection_types(
    alpha_setup_params: SetupParameters,
    beta_setup_params: SetupParameters,
    gamma_setup_params: SetupParameters,
) -> None:
    async with AsyncExitStack() as exit_stack:
        env = await setup_mesh_nodes(
            exit_stack, [alpha_setup_params, beta_setup_params, gamma_setup_params]
        )

        connection_alpha, connection_beta, connection_gamma = [
            conn.connection for conn in env.connections
        ]
        client_alpha, client_beta, client_gamma = env.clients
        alpha, beta, gamma = env.nodes

        async with Ping(connection_alpha, beta.ip_addresses[0]).run() as ping:
            await ping.wait_for_next_ping(60)
        async with Ping(connection_alpha, gamma.ip_addresses[0]).run() as ping:
            await ping.wait_for_next_ping(60)

        wg_server = config.WG_SERVER

        await asyncio.gather(
            client_alpha.connect_to_vpn(
                str(wg_server["ipv4"]),
                int(wg_server["port"]),
                str(wg_server["public_key"]),
            ),
            client_beta.connect_to_vpn(
                str(wg_server["ipv4"]),
                int(wg_server["port"]),
                str(wg_server["public_key"]),
            ),
            client_gamma.connect_to_vpn(
                str(wg_server["ipv4"]),
                int(wg_server["port"]),
                str(wg_server["public_key"]),
            ),
        )

        async with Ping(connection_alpha, beta.ip_addresses[0]).run() as ping:
            # TODO: change waiting time to `wait_long` after issue LLT-3879 is fixed
            await testing.wait_defined(ping.wait_for_next_ping(), 60)
        async with Ping(connection_alpha, gamma.ip_addresses[0]).run() as ping:
            await ping.wait_for_next_ping()
        async with Ping(connection_alpha, config.STUN_SERVER).run() as ping:
            await ping.wait_for_next_ping()

        async with Ping(connection_beta, alpha.ip_addresses[0]).run() as ping:
            # TODO: change waiting time to `wait_long` after issue LLT-3879 is fixed
            await testing.wait_defined(ping.wait_for_next_ping(), 60)
        async with Ping(connection_beta, config.STUN_SERVER).run() as ping:
            await ping.wait_for_next_ping()

        async with Ping(connection_gamma, alpha.ip_addresses[0]).run() as ping:
            await ping.wait_for_next_ping()
        async with Ping(connection_gamma, config.STUN_SERVER).run() as ping:
            await ping.wait_for_next_ping()

        for connection in [connection_alpha, connection_beta, connection_gamma]:
            public_ip = await testing.wait_long(
                stun.get(connection, config.STUN_SERVER)
            )
            assert (
                public_ip == wg_server["ipv4"]
            ), f"wrong public IP when connected to VPN {public_ip}"
