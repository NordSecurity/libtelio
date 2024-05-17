import asyncio
import config
import pytest
import timeouts
from contextlib import AsyncExitStack
from helpers import SetupParameters, setup_environment, setup_mesh_nodes, setup_api
from telio import AdapterType, PathType, PeerInfo, State, Client
from telio_features import TelioFeatures, Direct
from utils import stun
from utils.connection_tracker import ConnectionLimits
from utils.connection_util import generate_connection_tracker_config, ConnectionTag
from utils.ping import Ping
from utils.router import IPStack


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "alpha_setup_params",
    [
        pytest.param(
            SetupParameters(
                connection_tag=ConnectionTag.DOCKER_CONE_CLIENT_1,
                adapter_type=AdapterType.BoringTun,
                connection_tracker_config=generate_connection_tracker_config(
                    ConnectionTag.DOCKER_CONE_CLIENT_1,
                    derp_1_limits=ConnectionLimits(1, 1),
                ),
            )
        ),
        pytest.param(
            SetupParameters(
                connection_tag=ConnectionTag.DOCKER_CONE_CLIENT_1,
                adapter_type=AdapterType.LinuxNativeWg,
                connection_tracker_config=generate_connection_tracker_config(
                    ConnectionTag.DOCKER_CONE_CLIENT_1,
                    derp_1_limits=ConnectionLimits(1, 1),
                ),
            ),
            marks=pytest.mark.linux_native,
        ),
        pytest.param(
            SetupParameters(
                connection_tag=ConnectionTag.WINDOWS_VM_1,
                adapter_type=AdapterType.WindowsNativeWg,
                connection_tracker_config=generate_connection_tracker_config(
                    ConnectionTag.WINDOWS_VM_1,
                    derp_1_limits=ConnectionLimits(1, 1),
                ),
            ),
            marks=pytest.mark.windows,
        ),
        pytest.param(
            SetupParameters(
                connection_tag=ConnectionTag.WINDOWS_VM_1,
                adapter_type=AdapterType.WireguardGo,
                connection_tracker_config=generate_connection_tracker_config(
                    ConnectionTag.WINDOWS_VM_1,
                    derp_1_limits=ConnectionLimits(1, 1),
                ),
            ),
            marks=pytest.mark.windows,
        ),
        pytest.param(
            SetupParameters(
                connection_tag=ConnectionTag.MAC_VM,
                adapter_type=AdapterType.BoringTun,
                connection_tracker_config=generate_connection_tracker_config(
                    ConnectionTag.MAC_VM,
                    derp_1_limits=ConnectionLimits(1, 1),
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
async def test_event_content_meshnet(
    alpha_setup_params: SetupParameters, beta_setup_params: SetupParameters
) -> None:
    async with AsyncExitStack() as exit_stack:
        env = await setup_mesh_nodes(
            exit_stack, [alpha_setup_params, beta_setup_params]
        )
        api = env.api
        alpha, beta = env.nodes
        alpha.nickname = "alpha"
        beta.nickname = "BETA"
        client_alpha, client_beta = env.clients
        connection_alpha, connection_beta = [
            conn.connection for conn in env.connections
        ]

        async with Ping(connection_alpha, beta.ip_addresses[0]).run() as ping:
            await ping.wait_for_next_ping()
        async with Ping(connection_beta, alpha.ip_addresses[0]).run() as ping:
            await ping.wait_for_next_ping()

        assert client_alpha.get_node_state(beta.public_key) == PeerInfo(
            identifier=beta.id,
            public_key=beta.public_key,
            state=State.Connected,
            is_exit=False,
            is_vpn=False,
            ip_addresses=beta.ip_addresses,
            allowed_ips=env.api.get_allowed_ip_list(beta.ip_addresses),
            nickname="BETA",
            endpoint=None,
            hostname=beta.name + ".nord",
            allow_incoming_connections=True,
            allow_peer_send_files=True,
            path=PathType.Relay,
        )

        assert client_beta.get_node_state(alpha.public_key) == PeerInfo(
            identifier=alpha.id,
            public_key=alpha.public_key,
            state=State.Connected,
            is_exit=False,
            is_vpn=False,
            ip_addresses=alpha.ip_addresses,
            allowed_ips=env.api.get_allowed_ip_list(alpha.ip_addresses),
            nickname="alpha",
            endpoint=None,
            hostname=alpha.name + ".nord",
            allow_incoming_connections=True,
            allow_peer_send_files=True,
            path=PathType.Relay,
        )

        api.remove(beta.id)

        await client_alpha.set_meshmap(api.get_meshmap(alpha.id))

        with pytest.raises(asyncio.TimeoutError):
            async with Ping(connection_alpha, beta.ip_addresses[0]).run() as ping:
                await ping.wait_for_next_ping(5)

        await asyncio.sleep(1)

        assert client_alpha.get_node_state(beta.public_key) == PeerInfo(
            identifier=beta.id,
            public_key=beta.public_key,
            state=State.Disconnected,
            is_exit=False,
            is_vpn=False,
            ip_addresses=beta.ip_addresses,
            allowed_ips=env.api.get_allowed_ip_list(beta.ip_addresses),
            nickname="BETA",
            endpoint=None,
            hostname=beta.name + ".nord",
            allow_incoming_connections=True,
            allow_peer_send_files=True,
            path=PathType.Direct,
        )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "alpha_setup_params, alpha_public_ip",
    [
        pytest.param(
            SetupParameters(
                connection_tag=ConnectionTag.DOCKER_CONE_CLIENT_1,
                adapter_type=AdapterType.BoringTun,
                connection_tracker_config=generate_connection_tracker_config(
                    ConnectionTag.DOCKER_CONE_CLIENT_1,
                    vpn_1_limits=ConnectionLimits(1, 1),
                    stun_limits=ConnectionLimits(2, 2),
                ),
                is_meshnet=False,
            ),
            "10.0.254.1",
        ),
        pytest.param(
            SetupParameters(
                connection_tag=ConnectionTag.DOCKER_CONE_CLIENT_1,
                adapter_type=AdapterType.LinuxNativeWg,
                connection_tracker_config=generate_connection_tracker_config(
                    ConnectionTag.DOCKER_CONE_CLIENT_1,
                    vpn_1_limits=ConnectionLimits(1, 1),
                    stun_limits=ConnectionLimits(2, 2),
                ),
                is_meshnet=False,
            ),
            "10.0.254.1",
            marks=pytest.mark.linux_native,
        ),
        pytest.param(
            SetupParameters(
                connection_tag=ConnectionTag.WINDOWS_VM_1,
                adapter_type=AdapterType.WindowsNativeWg,
                connection_tracker_config=generate_connection_tracker_config(
                    ConnectionTag.WINDOWS_VM_1,
                    vpn_1_limits=ConnectionLimits(1, 1),
                    stun_limits=ConnectionLimits(2, 2),
                ),
                is_meshnet=False,
            ),
            "10.0.254.7",
            marks=[
                pytest.mark.windows,
            ],
        ),
        pytest.param(
            SetupParameters(
                connection_tag=ConnectionTag.WINDOWS_VM_1,
                adapter_type=AdapterType.WireguardGo,
                connection_tracker_config=generate_connection_tracker_config(
                    ConnectionTag.WINDOWS_VM_1,
                    vpn_1_limits=ConnectionLimits(1, 1),
                    stun_limits=ConnectionLimits(2, 2),
                ),
                is_meshnet=False,
            ),
            "10.0.254.7",
            marks=[
                pytest.mark.windows,
            ],
        ),
        pytest.param(
            SetupParameters(
                connection_tag=ConnectionTag.MAC_VM,
                adapter_type=AdapterType.BoringTun,
                connection_tracker_config=generate_connection_tracker_config(
                    ConnectionTag.MAC_VM,
                    vpn_1_limits=ConnectionLimits(1, 1),
                    stun_limits=ConnectionLimits(2, 2),
                ),
                is_meshnet=False,
            ),
            "10.0.254.7",
            marks=pytest.mark.mac,
        ),
    ],
)
async def test_event_content_vpn_connection(
    alpha_setup_params: SetupParameters, alpha_public_ip: str
) -> None:
    async with AsyncExitStack() as exit_stack:
        env = await exit_stack.enter_async_context(
            setup_environment(exit_stack, [alpha_setup_params])
        )
        connection, *_ = [conn.connection for conn in env.connections]
        client_alpha, *_ = env.clients

        ip: str = await stun.get(connection, config.STUN_SERVER)
        assert ip == alpha_public_ip, f"wrong public IP before connecting to VPN {ip}"

        wg_server = config.WG_SERVER

        await client_alpha.connect_to_vpn(
            str(wg_server["ipv4"]), int(wg_server["port"]), str(wg_server["public_key"])
        )

        async with Ping(connection, config.PHOTO_ALBUM_IP).run() as ping:
            await ping.wait_for_next_ping()

        assert client_alpha.get_node_state(str(wg_server["public_key"])) == PeerInfo(
            identifier="tcli",
            public_key=str(wg_server["public_key"]),
            state=State.Connected,
            is_exit=True,
            is_vpn=True,
            ip_addresses=[
                "10.5.0.1",
                "100.64.0.1",
            ],
            allowed_ips=["0.0.0.0/0", "::/0"],
            nickname=None,
            endpoint=f'{wg_server["ipv4"]}:{wg_server["port"]}',
            hostname=None,
            allow_incoming_connections=False,
            allow_peer_send_files=False,
            path=PathType.Direct,
        )

        ip = await stun.get(connection, config.STUN_SERVER)
        assert ip == wg_server["ipv4"], f"wrong public IP when connected to VPN {ip}"

        await client_alpha.disconnect_from_vpn(str(wg_server["public_key"]))

        ip = await stun.get(connection, config.STUN_SERVER)
        assert ip == alpha_public_ip, f"wrong public IP before connecting to VPN {ip}"

        assert client_alpha.get_node_state(str(wg_server["public_key"])) == PeerInfo(
            identifier="tcli",
            public_key=str(wg_server["public_key"]),
            state=State.Disconnected,
            is_exit=True,
            is_vpn=True,
            ip_addresses=[
                "10.5.0.1",
                "100.64.0.1",
            ],
            allowed_ips=["0.0.0.0/0", "::/0"],
            nickname=None,
            endpoint=f'{wg_server["ipv4"]}:{wg_server["port"]}',
            hostname=None,
            allow_incoming_connections=False,
            allow_peer_send_files=False,
            path=PathType.Direct,
        )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "alpha_setup_params",
    [
        pytest.param(
            SetupParameters(
                connection_tag=ConnectionTag.DOCKER_CONE_CLIENT_1,
                adapter_type=AdapterType.BoringTun,
                connection_tracker_config=generate_connection_tracker_config(
                    ConnectionTag.DOCKER_CONE_CLIENT_1,
                    derp_1_limits=ConnectionLimits(1, 1),
                ),
            )
        ),
        pytest.param(
            SetupParameters(
                connection_tag=ConnectionTag.DOCKER_CONE_CLIENT_1,
                adapter_type=AdapterType.LinuxNativeWg,
                connection_tracker_config=generate_connection_tracker_config(
                    ConnectionTag.DOCKER_CONE_CLIENT_1,
                    derp_1_limits=ConnectionLimits(1, 1),
                ),
            ),
            marks=pytest.mark.linux_native,
        ),
        pytest.param(
            SetupParameters(
                connection_tag=ConnectionTag.WINDOWS_VM_1,
                adapter_type=AdapterType.WindowsNativeWg,
                connection_tracker_config=generate_connection_tracker_config(
                    ConnectionTag.WINDOWS_VM_1,
                    derp_1_limits=ConnectionLimits(1, 1),
                ),
            ),
            marks=pytest.mark.windows,
        ),
        pytest.param(
            SetupParameters(
                connection_tag=ConnectionTag.WINDOWS_VM_1,
                adapter_type=AdapterType.WireguardGo,
                connection_tracker_config=generate_connection_tracker_config(
                    ConnectionTag.WINDOWS_VM_1,
                    derp_1_limits=ConnectionLimits(1, 1),
                ),
            ),
            marks=pytest.mark.windows,
        ),
        pytest.param(
            SetupParameters(
                connection_tag=ConnectionTag.MAC_VM,
                adapter_type=AdapterType.BoringTun,
                connection_tracker_config=generate_connection_tracker_config(
                    ConnectionTag.MAC_VM,
                    derp_1_limits=ConnectionLimits(1, 1),
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
                    stun_limits=ConnectionLimits(2, 2),
                ),
            )
        )
    ],
)
async def test_event_content_exit_through_peer(
    alpha_setup_params: SetupParameters, beta_setup_params: SetupParameters
) -> None:
    async with AsyncExitStack() as exit_stack:
        api, (alpha, beta) = setup_api(
            [(False, IPStack.IPv4v6), (False, IPStack.IPv4v6)]
        )
        alpha.nickname = "alpha"
        beta.nickname = "BETA"
        alpha.set_peer_firewall_settings(beta.id)
        env = await setup_mesh_nodes(
            exit_stack, [alpha_setup_params, beta_setup_params], provided_api=api
        )
        connection_alpha, connection_beta = [
            conn.connection for conn in env.connections
        ]
        client_alpha, client_beta = env.clients

        async with Ping(connection_alpha, beta.ip_addresses[0]).run() as ping:
            await ping.wait_for_next_ping()

        assert client_alpha.get_node_state(beta.public_key) == PeerInfo(
            identifier=beta.id,
            public_key=beta.public_key,
            state=State.Connected,
            is_exit=False,
            is_vpn=False,
            ip_addresses=beta.ip_addresses,
            allowed_ips=env.api.get_allowed_ip_list(beta.ip_addresses),
            nickname="BETA",
            endpoint=None,
            hostname=beta.name + ".nord",
            allow_incoming_connections=False,
            allow_peer_send_files=False,
            path=PathType.Relay,
        )

        await client_beta.get_router().create_exit_node_route()

        await client_alpha.connect_to_exit_node(beta.public_key)

        ip_alpha = await stun.get(connection_alpha, config.STUN_SERVER)
        ip_beta = await stun.get(connection_beta, config.STUN_SERVER)

        assert ip_alpha == ip_beta

        assert client_alpha.get_node_state(beta.public_key) == PeerInfo(
            identifier=beta.id,
            public_key=beta.public_key,
            state=State.Connected,
            is_exit=True,
            is_vpn=False,
            ip_addresses=beta.ip_addresses,
            allowed_ips=["0.0.0.0/0", "::/0"],
            nickname="BETA",
            endpoint=None,
            hostname=beta.name + ".nord",
            allow_incoming_connections=False,
            allow_peer_send_files=False,
            path=PathType.Relay,
        )


@pytest.mark.asyncio
@pytest.mark.timeout(timeouts.TEST_EVENT_CONTENT_MESHNET_NODE_UPGRADE_DIRECT_TIMEOUT)
@pytest.mark.parametrize(
    "alpha_setup_params, alpha_public_ip",
    [
        pytest.param(
            SetupParameters(
                connection_tag=ConnectionTag.DOCKER_CONE_CLIENT_1,
                adapter_type=AdapterType.BoringTun,
                connection_tracker_config=generate_connection_tracker_config(
                    ConnectionTag.DOCKER_CONE_CLIENT_1,
                    derp_1_limits=ConnectionLimits(1, 1),
                ),
                features=TelioFeatures(direct=Direct(providers=["stun"])),
            ),
            "10.0.254.1",
        ),
        pytest.param(
            SetupParameters(
                connection_tag=ConnectionTag.DOCKER_CONE_CLIENT_1,
                adapter_type=AdapterType.LinuxNativeWg,
                connection_tracker_config=generate_connection_tracker_config(
                    ConnectionTag.DOCKER_CONE_CLIENT_1,
                    derp_1_limits=ConnectionLimits(1, 1),
                ),
                features=TelioFeatures(direct=Direct(providers=["stun"])),
            ),
            "10.0.254.1",
            marks=pytest.mark.linux_native,
        ),
        pytest.param(
            SetupParameters(
                connection_tag=ConnectionTag.WINDOWS_VM_1,
                adapter_type=AdapterType.WindowsNativeWg,
                connection_tracker_config=generate_connection_tracker_config(
                    ConnectionTag.WINDOWS_VM_1,
                    derp_1_limits=ConnectionLimits(1, 1),
                ),
                features=TelioFeatures(direct=Direct(providers=["stun"])),
            ),
            "10.0.254.7",
            marks=pytest.mark.windows,
        ),
        pytest.param(
            SetupParameters(
                connection_tag=ConnectionTag.WINDOWS_VM_1,
                adapter_type=AdapterType.WireguardGo,
                connection_tracker_config=generate_connection_tracker_config(
                    ConnectionTag.WINDOWS_VM_1,
                    derp_1_limits=ConnectionLimits(1, 1),
                ),
                features=TelioFeatures(direct=Direct(providers=["stun"])),
            ),
            "10.0.254.7",
            marks=pytest.mark.windows,
        ),
        pytest.param(
            SetupParameters(
                connection_tag=ConnectionTag.MAC_VM,
                adapter_type=AdapterType.BoringTun,
                connection_tracker_config=generate_connection_tracker_config(
                    ConnectionTag.MAC_VM,
                    derp_1_limits=ConnectionLimits(1, 1),
                ),
                features=TelioFeatures(direct=Direct(providers=["stun"])),
            ),
            "10.0.254.7",
            marks=[pytest.mark.mac],
        ),
    ],
)
@pytest.mark.parametrize(
    "beta_setup_params, beta_public_ip",
    [
        pytest.param(
            SetupParameters(
                connection_tag=ConnectionTag.DOCKER_CONE_CLIENT_2,
                connection_tracker_config=generate_connection_tracker_config(
                    ConnectionTag.DOCKER_CONE_CLIENT_2,
                    derp_1_limits=ConnectionLimits(2, 2),
                ),
            ),
            "10.0.254.2",
        )
    ],
)
async def test_event_content_meshnet_node_upgrade_direct(
    alpha_setup_params: SetupParameters,
    alpha_public_ip: str,
    beta_setup_params: SetupParameters,
    beta_public_ip: str,
) -> None:
    async with AsyncExitStack() as exit_stack:
        env = await setup_mesh_nodes(
            exit_stack, [alpha_setup_params, beta_setup_params]
        )

        api = env.api
        alpha, beta = env.nodes
        alpha.nickname = "alpha"
        beta.nickname = "BETA"
        connection_alpha, connection_beta = [
            conn.connection for conn in env.connections
        ]
        client_alpha, client_beta = env.clients

        async with Ping(connection_alpha, beta.ip_addresses[0]).run() as ping:
            await ping.wait_for_next_ping()
        async with Ping(connection_beta, alpha.ip_addresses[0]).run() as ping:
            await ping.wait_for_next_ping()

        beta_node_state = client_alpha.get_node_state(beta.public_key)
        assert beta_node_state
        assert beta_node_state == PeerInfo(
            identifier=beta.id,
            public_key=beta.public_key,
            state=State.Connected,
            is_exit=False,
            is_vpn=False,
            ip_addresses=beta.ip_addresses,
            allowed_ips=env.api.get_allowed_ip_list(beta.ip_addresses),
            nickname="BETA",
            endpoint=None,
            hostname=beta.name + ".nord",
            allow_incoming_connections=True,
            allow_peer_send_files=True,
            path=PathType.Relay,
        )
        assert (
            beta_node_state.endpoint and beta_public_ip not in beta_node_state.endpoint
        )

        alpha_node_state = client_beta.get_node_state(alpha.public_key)
        assert alpha_node_state
        assert alpha_node_state == PeerInfo(
            identifier=alpha.id,
            public_key=alpha.public_key,
            state=State.Connected,
            is_exit=False,
            is_vpn=False,
            ip_addresses=alpha.ip_addresses,
            allowed_ips=env.api.get_allowed_ip_list(alpha.ip_addresses),
            nickname="alpha",
            endpoint=None,
            hostname=alpha.name + ".nord",
            allow_incoming_connections=True,
            allow_peer_send_files=True,
            path=PathType.Relay,
        )
        assert (
            alpha_node_state.endpoint
            and alpha_public_ip not in alpha_node_state.endpoint
        )

        await client_beta.stop_device()
        del client_beta

        client_beta = await exit_stack.enter_async_context(
            Client(
                connection_beta,
                beta,
                telio_features=TelioFeatures(direct=Direct(providers=["stun"])),
            ).run(api.get_meshmap(beta.id))
        )

        await client_beta.wait_for_state_on_any_derp([State.Connected])

        await asyncio.gather(
            client_alpha.wait_for_state_peer(
                beta.public_key, [State.Connected], [PathType.Direct]
            ),
            client_beta.wait_for_state_peer(
                alpha.public_key, [State.Connected], [PathType.Direct]
            ),
        )

        async with Ping(connection_alpha, beta.ip_addresses[0]).run() as ping:
            await ping.wait_for_next_ping()
        async with Ping(connection_beta, alpha.ip_addresses[0]).run() as ping:
            await ping.wait_for_next_ping()

        beta_node_state = client_alpha.get_node_state(beta.public_key)
        assert beta_node_state
        assert beta_node_state == PeerInfo(
            identifier=beta.id,
            public_key=beta.public_key,
            state=State.Connected,
            is_exit=False,
            is_vpn=False,
            ip_addresses=beta.ip_addresses,
            allowed_ips=env.api.get_allowed_ip_list(beta.ip_addresses),
            nickname="BETA",
            endpoint=None,
            hostname=beta.name + ".nord",
            allow_incoming_connections=True,
            allow_peer_send_files=True,
            path=PathType.Direct,
        )
        assert beta_node_state.endpoint and beta_public_ip in beta_node_state.endpoint

        alpha_node_state = client_beta.get_node_state(alpha.public_key)
        assert alpha_node_state
        assert alpha_node_state == PeerInfo(
            identifier=alpha.id,
            public_key=alpha.public_key,
            state=State.Connected,
            is_exit=False,
            is_vpn=False,
            ip_addresses=alpha.ip_addresses,
            allowed_ips=env.api.get_allowed_ip_list(alpha.ip_addresses),
            nickname="alpha",
            endpoint=None,
            hostname=alpha.name + ".nord",
            allow_incoming_connections=True,
            allow_peer_send_files=True,
            path=PathType.Direct,
        )
        assert (
            alpha_node_state.endpoint and alpha_public_ip in alpha_node_state.endpoint
        )
