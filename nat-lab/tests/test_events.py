import asyncio
import config
import pytest
import timeouts
from contextlib import AsyncExitStack
from helpers import SetupParameters, setup_environment, setup_mesh_nodes, setup_api
from mesh_api import API
from telio import Client
from utils import stun
from utils.bindings import (
    features_with_endpoint_providers,
    EndpointProvider,
    PathType,
    TelioNode,
    NodeState,
    RelayState,
    telio_node,
    TelioAdapterType,
)
from utils.connection_tracker import ConnectionLimits
from utils.connection_util import (
    generate_connection_tracker_config,
    ConnectionTag,
    new_connection_with_conn_tracker,
)
from utils.ping import ping
from utils.router import IPStack


def node_cmp(left: TelioNode, right: TelioNode):
    return (
        left.identifier == right.identifier
        and left.public_key == right.public_key
        and left.state == right.state
        and (
            left.link_state is None
            or right.link_state is None
            or left.link_state == right.link_state
        )
        and left.is_exit == right.is_exit
        and left.is_vpn == right.is_vpn
        and left.ip_addresses == right.ip_addresses
        and left.allowed_ips == right.allowed_ips
        and (
            left.endpoint is None
            or right.endpoint is None
            or left.endpoint == right.endpoint
        )
        and (
            left.hostname is None
            or right.hostname is None
            or left.hostname == right.hostname
        )
        and (
            left.nickname is None
            or right.nickname is None
            or left.nickname == right.nickname
        )
        and left.allow_incoming_connections == right.allow_incoming_connections
        and left.allow_peer_send_files == right.allow_peer_send_files
        and left.path == right.path
    )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "alpha_setup_params",
    [
        pytest.param(
            SetupParameters(
                connection_tag=ConnectionTag.DOCKER_CONE_CLIENT_1,
                adapter_type_override=TelioAdapterType.BORING_TUN,
                connection_tracker_config=generate_connection_tracker_config(
                    ConnectionTag.DOCKER_CONE_CLIENT_1,
                    derp_1_limits=ConnectionLimits(1, 1),
                ),
            )
        ),
        pytest.param(
            SetupParameters(
                connection_tag=ConnectionTag.DOCKER_CONE_CLIENT_1,
                adapter_type_override=TelioAdapterType.LINUX_NATIVE_TUN,
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
                adapter_type_override=TelioAdapterType.WINDOWS_NATIVE_TUN,
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
                adapter_type_override=TelioAdapterType.WIREGUARD_GO_TUN,
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
                adapter_type_override=TelioAdapterType.BORING_TUN,
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

        await ping(connection_alpha, beta.ip_addresses[0])
        await ping(connection_beta, alpha.ip_addresses[0])

        beta_node_state = client_alpha.get_node_state(beta.public_key)
        assert beta_node_state
        assert node_cmp(
            beta_node_state,
            telio_node(
                identifier=beta.id,
                public_key=beta.public_key,
                state=NodeState.CONNECTED,
                ip_addresses=beta.ip_addresses,
                allowed_ips=env.api.get_allowed_ip_list(beta.ip_addresses),
                nickname="BETA",
                hostname=beta.name + ".nord",
                allow_incoming_connections=True,
                allow_peer_send_files=True,
            ),
        )

        alpha_node_state = client_beta.get_node_state(alpha.public_key)
        assert alpha_node_state
        assert node_cmp(
            alpha_node_state,
            telio_node(
                identifier=alpha.id,
                public_key=alpha.public_key,
                state=NodeState.CONNECTED,
                ip_addresses=alpha.ip_addresses,
                allowed_ips=env.api.get_allowed_ip_list(alpha.ip_addresses),
                nickname="alpha",
                hostname=alpha.name + ".nord",
                allow_incoming_connections=True,
                allow_peer_send_files=True,
            ),
        )

        api.remove(beta.id)

        await client_alpha.set_meshnet_config(api.get_meshnet_config(alpha.id))

        with pytest.raises(asyncio.TimeoutError):
            await ping(connection_alpha, beta.ip_addresses[0], 5)

        await asyncio.sleep(1)

        beta_node_state = client_alpha.get_node_state(beta.public_key)
        assert beta_node_state
        assert node_cmp(
            beta_node_state,
            telio_node(
                identifier=beta.id,
                public_key=beta.public_key,
                state=NodeState.DISCONNECTED,
                ip_addresses=beta.ip_addresses,
                allowed_ips=env.api.get_allowed_ip_list(beta.ip_addresses),
                nickname="BETA",
                hostname=beta.name + ".nord",
                allow_incoming_connections=True,
                allow_peer_send_files=True,
                path=PathType.DIRECT,
            ),
        )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "alpha_setup_params, alpha_public_ip",
    [
        pytest.param(
            SetupParameters(
                connection_tag=ConnectionTag.DOCKER_CONE_CLIENT_1,
                adapter_type_override=TelioAdapterType.BORING_TUN,
                connection_tracker_config=generate_connection_tracker_config(
                    ConnectionTag.DOCKER_CONE_CLIENT_1,
                    vpn_1_limits=ConnectionLimits(1, 1),
                    stun_limits=ConnectionLimits(1, 2),
                ),
                is_meshnet=False,
            ),
            "10.0.254.1",
        ),
        pytest.param(
            SetupParameters(
                connection_tag=ConnectionTag.DOCKER_CONE_CLIENT_1,
                adapter_type_override=TelioAdapterType.LINUX_NATIVE_TUN,
                connection_tracker_config=generate_connection_tracker_config(
                    ConnectionTag.DOCKER_CONE_CLIENT_1,
                    vpn_1_limits=ConnectionLimits(1, 1),
                    stun_limits=ConnectionLimits(1, 2),
                ),
                is_meshnet=False,
            ),
            "10.0.254.1",
            marks=pytest.mark.linux_native,
        ),
        pytest.param(
            SetupParameters(
                connection_tag=ConnectionTag.WINDOWS_VM_1,
                adapter_type_override=TelioAdapterType.WINDOWS_NATIVE_TUN,
                connection_tracker_config=generate_connection_tracker_config(
                    ConnectionTag.WINDOWS_VM_1,
                    vpn_1_limits=ConnectionLimits(1, 1),
                    stun_limits=ConnectionLimits(1, 2),
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
                adapter_type_override=TelioAdapterType.WIREGUARD_GO_TUN,
                connection_tracker_config=generate_connection_tracker_config(
                    ConnectionTag.WINDOWS_VM_1,
                    vpn_1_limits=ConnectionLimits(1, 1),
                    stun_limits=ConnectionLimits(1, 2),
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
                adapter_type_override=TelioAdapterType.BORING_TUN,
                connection_tracker_config=generate_connection_tracker_config(
                    ConnectionTag.MAC_VM,
                    vpn_1_limits=ConnectionLimits(1, 1),
                    stun_limits=ConnectionLimits(1, 2),
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

        await ping(connection, config.PHOTO_ALBUM_IP)

        wg_node_state = client_alpha.get_node_state(str(wg_server["public_key"]))
        assert wg_node_state
        assert node_cmp(
            wg_node_state,
            telio_node(
                identifier="natlab",
                public_key=str(wg_server["public_key"]),
                state=NodeState.CONNECTED,
                is_exit=True,
                is_vpn=True,
                ip_addresses=[
                    "10.5.0.1",
                    "100.64.0.1",
                ],
                allowed_ips=["0.0.0.0/0", "::/0"],
                endpoint=f'{wg_server["ipv4"]}:{wg_server["port"]}',
                path=PathType.DIRECT,
            ),
        )

        ip = await stun.get(connection, config.STUN_SERVER)
        assert ip == wg_server["ipv4"], f"wrong public IP when connected to VPN {ip}"

        await client_alpha.disconnect_from_vpn(str(wg_server["public_key"]))

        ip = await stun.get(connection, config.STUN_SERVER)
        assert ip == alpha_public_ip, f"wrong public IP before connecting to VPN {ip}"

        wg_node_state = client_alpha.get_node_state(str(wg_server["public_key"]))
        assert wg_node_state
        assert node_cmp(
            wg_node_state,
            telio_node(
                identifier="natlab",
                public_key=str(wg_server["public_key"]),
                is_exit=True,
                is_vpn=True,
                ip_addresses=[
                    "10.5.0.1",
                    "100.64.0.1",
                ],
                allowed_ips=["0.0.0.0/0", "::/0"],
                endpoint=f'{wg_server["ipv4"]}:{wg_server["port"]}',
                path=PathType.DIRECT,
            ),
        )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "alpha_setup_params",
    [
        pytest.param(
            SetupParameters(
                connection_tag=ConnectionTag.DOCKER_CONE_CLIENT_1,
                adapter_type_override=TelioAdapterType.BORING_TUN,
                connection_tracker_config=generate_connection_tracker_config(
                    ConnectionTag.DOCKER_CONE_CLIENT_1,
                    derp_1_limits=ConnectionLimits(1, 1),
                ),
            )
        ),
        pytest.param(
            SetupParameters(
                connection_tag=ConnectionTag.DOCKER_CONE_CLIENT_1,
                adapter_type_override=TelioAdapterType.LINUX_NATIVE_TUN,
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
                adapter_type_override=TelioAdapterType.WINDOWS_NATIVE_TUN,
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
                adapter_type_override=TelioAdapterType.WIREGUARD_GO_TUN,
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
                adapter_type_override=TelioAdapterType.BORING_TUN,
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
                    stun_limits=ConnectionLimits(1, 2),
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

        await ping(connection_alpha, beta.ip_addresses[0])

        beta_node_state = client_alpha.get_node_state(beta.public_key)
        assert beta_node_state
        assert node_cmp(
            beta_node_state,
            telio_node(
                identifier=beta.id,
                public_key=beta.public_key,
                state=NodeState.CONNECTED,
                ip_addresses=beta.ip_addresses,
                allowed_ips=env.api.get_allowed_ip_list(beta.ip_addresses),
                nickname="BETA",
                hostname=beta.name + ".nord",
            ),
        )

        await client_beta.get_router().create_exit_node_route()

        await client_alpha.connect_to_exit_node(beta.public_key)

        ip_alpha = await stun.get(connection_alpha, config.STUN_SERVER)
        ip_beta = await stun.get(connection_beta, config.STUN_SERVER)

        assert ip_alpha == ip_beta

        beta_node_state = client_alpha.get_node_state(beta.public_key)
        assert beta_node_state
        assert node_cmp(
            beta_node_state,
            telio_node(
                identifier=beta.id,
                public_key=beta.public_key,
                state=NodeState.CONNECTED,
                is_exit=True,
                ip_addresses=beta.ip_addresses,
                allowed_ips=["0.0.0.0/0", "::/0"],
                nickname="BETA",
                hostname=beta.name + ".nord",
            ),
        )


@pytest.mark.asyncio
@pytest.mark.timeout(timeouts.TEST_EVENT_CONTENT_MESHNET_NODE_UPGRADE_DIRECT_TIMEOUT)
@pytest.mark.parametrize(
    "alpha_setup_params, alpha_public_ip",
    [
        pytest.param(
            SetupParameters(
                connection_tag=ConnectionTag.DOCKER_CONE_CLIENT_1,
                adapter_type_override=TelioAdapterType.BORING_TUN,
                connection_tracker_config=generate_connection_tracker_config(
                    ConnectionTag.DOCKER_CONE_CLIENT_1,
                    derp_1_limits=ConnectionLimits(1, 1),
                ),
                features=features_with_endpoint_providers([EndpointProvider.STUN]),
            ),
            "10.0.254.1",
        ),
        pytest.param(
            SetupParameters(
                connection_tag=ConnectionTag.DOCKER_CONE_CLIENT_1,
                adapter_type_override=TelioAdapterType.LINUX_NATIVE_TUN,
                connection_tracker_config=generate_connection_tracker_config(
                    ConnectionTag.DOCKER_CONE_CLIENT_1,
                    derp_1_limits=ConnectionLimits(1, 1),
                ),
                features=features_with_endpoint_providers([EndpointProvider.STUN]),
            ),
            "10.0.254.1",
            marks=pytest.mark.linux_native,
        ),
        pytest.param(
            SetupParameters(
                connection_tag=ConnectionTag.WINDOWS_VM_1,
                adapter_type_override=TelioAdapterType.WINDOWS_NATIVE_TUN,
                connection_tracker_config=generate_connection_tracker_config(
                    ConnectionTag.WINDOWS_VM_1,
                    derp_1_limits=ConnectionLimits(1, 1),
                ),
                features=features_with_endpoint_providers([EndpointProvider.STUN]),
            ),
            "10.0.254.7",
            marks=pytest.mark.windows,
        ),
        pytest.param(
            SetupParameters(
                connection_tag=ConnectionTag.WINDOWS_VM_1,
                adapter_type_override=TelioAdapterType.WIREGUARD_GO_TUN,
                connection_tracker_config=generate_connection_tracker_config(
                    ConnectionTag.WINDOWS_VM_1,
                    derp_1_limits=ConnectionLimits(1, 1),
                ),
                features=features_with_endpoint_providers([EndpointProvider.STUN]),
            ),
            "10.0.254.7",
            marks=pytest.mark.windows,
        ),
        pytest.param(
            SetupParameters(
                connection_tag=ConnectionTag.MAC_VM,
                adapter_type_override=TelioAdapterType.BORING_TUN,
                connection_tracker_config=generate_connection_tracker_config(
                    ConnectionTag.MAC_VM,
                    derp_1_limits=ConnectionLimits(1, 1),
                ),
                features=features_with_endpoint_providers([EndpointProvider.STUN]),
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
                    derp_1_limits=ConnectionLimits(1, 2),
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
        api = API()
        (alpha, beta) = api.default_config_two_nodes(
            alpha_setup_params.is_local,
            beta_setup_params.is_local,
            alpha_setup_params.ip_stack,
            beta_setup_params.ip_stack,
        )
        alpha.set_peer_firewall_settings(beta.id, True, True)
        beta.set_peer_firewall_settings(alpha.id, True, True)
        (connection_alpha, alpha_conn_tracker) = await exit_stack.enter_async_context(
            new_connection_with_conn_tracker(
                alpha_setup_params.connection_tag,
                alpha_setup_params.connection_tracker_config,
            )
        )
        (connection_beta, beta_conn_tracker) = await exit_stack.enter_async_context(
            new_connection_with_conn_tracker(
                beta_setup_params.connection_tag,
                beta_setup_params.connection_tracker_config,
            )
        )
        alpha.nickname = "alpha"
        beta.nickname = "BETA"

        client_alpha = await exit_stack.enter_async_context(
            Client(
                connection_alpha,
                alpha,
                alpha_setup_params.adapter_type_override,
                alpha_setup_params.features,
            ).run(api.get_meshnet_config(alpha.id))
        )

        async with Client(
            connection_beta,
            beta,
            beta_setup_params.adapter_type_override,
            beta_setup_params.features,
        ).run(api.get_meshnet_config(beta.id)) as client_beta:
            await asyncio.gather(
                client_alpha.wait_for_state_on_any_derp([RelayState.CONNECTED]),
                client_beta.wait_for_state_on_any_derp([RelayState.CONNECTED]),
            )
            await asyncio.gather(
                client_alpha.wait_for_state_peer(
                    beta.public_key, [NodeState.CONNECTED]
                ),
                client_beta.wait_for_state_peer(
                    alpha.public_key, [NodeState.CONNECTED]
                ),
            )

            await ping(connection_alpha, beta.ip_addresses[0], 10)
            await ping(connection_beta, alpha.ip_addresses[0], 10)

            beta_node_state = client_alpha.get_node_state(beta.public_key)
            assert beta_node_state
            assert node_cmp(
                beta_node_state,
                telio_node(
                    identifier=beta.id,
                    public_key=beta.public_key,
                    state=NodeState.CONNECTED,
                    ip_addresses=beta.ip_addresses,
                    allowed_ips=api.get_allowed_ip_list(beta.ip_addresses),
                    nickname="BETA",
                    hostname=beta.name + ".nord",
                    allow_incoming_connections=True,
                    allow_peer_send_files=True,
                ),
            )
            assert (
                beta_node_state.endpoint
                and beta_public_ip not in beta_node_state.endpoint
            )

            alpha_node_state = client_beta.get_node_state(alpha.public_key)
            assert alpha_node_state
            assert node_cmp(
                alpha_node_state,
                telio_node(
                    identifier=alpha.id,
                    public_key=alpha.public_key,
                    state=NodeState.CONNECTED,
                    ip_addresses=alpha.ip_addresses,
                    allowed_ips=api.get_allowed_ip_list(alpha.ip_addresses),
                    nickname="alpha",
                    hostname=alpha.name + ".nord",
                    allow_incoming_connections=True,
                    allow_peer_send_files=True,
                ),
            )
            assert (
                alpha_node_state.endpoint
                and alpha_public_ip not in alpha_node_state.endpoint
            )

        client_beta = await exit_stack.enter_async_context(
            Client(
                connection_beta,
                beta,
                telio_features=features_with_endpoint_providers(
                    [EndpointProvider.STUN]
                ),
            ).run(api.get_meshnet_config(beta.id))
        )

        await client_beta.wait_for_state_on_any_derp([RelayState.CONNECTED])

        await asyncio.gather(
            client_alpha.wait_for_state_peer(
                beta.public_key, [NodeState.CONNECTED], [PathType.DIRECT]
            ),
            client_beta.wait_for_state_peer(
                alpha.public_key, [NodeState.CONNECTED], [PathType.DIRECT]
            ),
        )

        await ping(connection_alpha, beta.ip_addresses[0])
        await ping(connection_beta, alpha.ip_addresses[0])

        beta_node_state = client_alpha.get_node_state(beta.public_key)
        assert beta_node_state
        assert node_cmp(
            beta_node_state,
            telio_node(
                identifier=beta.id,
                public_key=beta.public_key,
                state=NodeState.CONNECTED,
                ip_addresses=beta.ip_addresses,
                allowed_ips=api.get_allowed_ip_list(beta.ip_addresses),
                nickname="BETA",
                hostname=beta.name + ".nord",
                allow_incoming_connections=True,
                allow_peer_send_files=True,
                path=PathType.DIRECT,
            ),
        )
        assert beta_node_state.endpoint and beta_public_ip in beta_node_state.endpoint

        alpha_node_state = client_beta.get_node_state(alpha.public_key)
        assert alpha_node_state
        assert node_cmp(
            alpha_node_state,
            telio_node(
                identifier=alpha.id,
                public_key=alpha.public_key,
                state=NodeState.CONNECTED,
                ip_addresses=alpha.ip_addresses,
                allowed_ips=api.get_allowed_ip_list(alpha.ip_addresses),
                nickname="alpha",
                hostname=alpha.name + ".nord",
                allow_incoming_connections=True,
                allow_peer_send_files=True,
                path=PathType.DIRECT,
            ),
        )
        assert (
            alpha_node_state.endpoint and alpha_public_ip in alpha_node_state.endpoint
        )

        assert await alpha_conn_tracker.get_out_of_limits() is None
        assert await beta_conn_tracker.get_out_of_limits() is None
