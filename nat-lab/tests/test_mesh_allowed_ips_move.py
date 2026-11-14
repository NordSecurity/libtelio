import pytest
from contextlib import AsyncExitStack
from dataclasses import replace
from ipaddress import IPv4Network, IPv6Network, ip_network
from tests import config
from tests.helpers import Environment, SetupParameters, setup_api, setup_environment
from tests.libtelio_client import Client
from tests.mesh_api import API, Node
from tests.uniffi.libtelio_proxy import LibtelioError
from tests.utils import stun
from tests.utils.bindings import (
    Config,
    NodeState,
    RelayState,
    TelioAdapterType,
    default_features,
)
from tests.utils.connection import Connection, ConnectionTag
from tests.utils.ping import ping
from typing import Awaitable, Callable, Dict, List, Set, Union

LINUX_ALPHA_SETUP_PARAMS = [
    pytest.param(
        SetupParameters(
            connection_tag=ConnectionTag.DOCKER_CONE_CLIENT_1,
            adapter_type_override=TelioAdapterType.NEP_TUN,
        ),
        id="neptun",
    ),
    pytest.param(
        SetupParameters(
            connection_tag=ConnectionTag.DOCKER_CONE_CLIENT_1,
            adapter_type_override=TelioAdapterType.LINUX_NATIVE_TUN,
        ),
        marks=pytest.mark.linux_native,
        id="linux_native",
    ),
]

WINDOWS_ALPHA_SETUP_PARAMS = [
    pytest.param(
        SetupParameters(
            connection_tag=ConnectionTag.VM_WINDOWS_1,
            adapter_type_override=TelioAdapterType.WINDOWS_NATIVE_TUN,
        ),
        marks=pytest.mark.windows,
        id="windows_native",
    ),
]

MAC_ALPHA_SETUP_PARAMS = [
    pytest.param(
        SetupParameters(
            connection_tag=ConnectionTag.VM_MAC,
            adapter_type_override=TelioAdapterType.NEP_TUN,
        ),
        marks=pytest.mark.mac,
        id="mac",
    ),
]

ALPHA_SETUP_PARAMS = (
    LINUX_ALPHA_SETUP_PARAMS + WINDOWS_ALPHA_SETUP_PARAMS + MAC_ALPHA_SETUP_PARAMS
)

BETA_SETUP_PARAMS = [
    pytest.param(
        SetupParameters(connection_tag=ConnectionTag.DOCKER_CONE_CLIENT_2),
        id="beta",
    )
]

EXIT_NODE_BETA_SETUP_PARAMS = [
    pytest.param(
        SetupParameters(
            connection_tag=ConnectionTag.DOCKER_CONE_CLIENT_2,
            features=default_features(enable_firewall_exclusion_range="10.0.0.0/8"),
        ),
        id="beta",
    )
]

GAMMA_SETUP_PARAMS = [
    pytest.param(
        SetupParameters(connection_tag=ConnectionTag.DOCKER_SYMMETRIC_CLIENT_1),
        id="gamma",
    )
]


# Module-level override, the tests using env_mesh get VPN_1
@pytest.fixture(name="vpn_tags")
def _vpn_tags() -> List[ConnectionTag]:
    return [ConnectionTag.DOCKER_VPN_1]


def meshnet_config_with_peer_ips(
    meshnet_config: Config, peer_ips: Dict[str, List[str]]
) -> Config:
    """Limit the config to the given peers (by public key) and replace their meshnet IPs."""
    assert meshnet_config.peers is not None
    meshnet_config.peers = [
        peer for peer in meshnet_config.peers if peer.base.public_key in peer_ips
    ]
    for peer in meshnet_config.peers:
        peer.base.ip_addresses = peer_ips[peer.base.public_key]
    return meshnet_config


def to_networks(allowed_ips: List[str]) -> Set[Union[IPv4Network, IPv6Network]]:
    return {ip_network(allowed_ip) for allowed_ip in allowed_ips}


def assert_peer_holds_ips_of(client: Client, peer: Node, ips_owner: Node) -> None:
    """Check that the client sees the peer with the meshnet IPs of ips_owner as its allowed IPs."""
    node_state = client.get_node_state(peer.public_key)
    assert node_state
    assert node_state.allowed_ips
    assert to_networks(node_state.allowed_ips) <= to_networks(
        API.get_allowed_ip_list(ips_owner.ip_addresses)
    ), f"{peer.name} has allowed IPs {node_state.allowed_ips}"


async def connect_to_vpn(client: Client, connection: Connection) -> None:
    wg_server = config.WG_SERVER
    await client.vpn.connect(
        str(wg_server["ipv4"]), int(wg_server["port"]), str(wg_server["public_key"])
    )

    public_ip = await stun.get(connection, config.STUN_SERVER)
    assert (
        public_ip == wg_server["ipv4"]
    ), f"wrong public IP when connected to VPN {public_ip}"


async def start_alpha_with_stale_peer_ips(
    exit_stack: AsyncExitStack,
    alpha_setup_params: SetupParameters,
    beta_setup_params: SetupParameters,
    gamma_setup_params: SetupParameters,
    stale_peer_ips: Callable[[Node, Node], Dict[str, List[str]]],
) -> Environment:
    """Start a mesh in which only alpha has an outdated view of who holds which meshnet IP.

    The other nodes run with the real config from the start, so the test only has to change
    the config of alpha to move the IPs to their real owners.
    """
    api, (alpha, beta, gamma) = setup_api([
        (False, alpha_setup_params.ip_stack),
        (False, beta_setup_params.ip_stack),
        (False, gamma_setup_params.ip_stack),
    ])

    env = await exit_stack.enter_async_context(
        setup_environment(
            exit_stack,
            [
                replace(alpha_setup_params, is_meshnet=False),
                beta_setup_params,
                gamma_setup_params,
            ],
            provided_api=api,
        )
    )

    client_alpha, *_ = env.clients
    stale_config = meshnet_config_with_peer_ips(
        api.get_meshnet_config(alpha.id), stale_peer_ips(beta, gamma)
    )
    await client_alpha.set_meshnet_config(stale_config)
    await client_alpha.events.wait_for_state_on_any_derp([RelayState.CONNECTED])
    assert stale_config.peers is not None
    for peer in stale_config.peers:
        await client_alpha.events.wait_for_state_peer(
            peer.base.public_key, [NodeState.CONNECTED]
        )

    return env


# The mac router can not create the VPN route twice, and this test needs it for both exit nodes
@pytest.mark.asyncio
@pytest.mark.parametrize(
    "alpha_setup_params", LINUX_ALPHA_SETUP_PARAMS + WINDOWS_ALPHA_SETUP_PARAMS
)
@pytest.mark.parametrize("beta_setup_params", EXIT_NODE_BETA_SETUP_PARAMS)
async def test_exit_node_switch_from_meshnet_peer_to_vpn(
    setup_mesh_nodes_factory: Callable[..., Awaitable[Environment]],
    alpha_setup_params: SetupParameters,
    beta_setup_params: SetupParameters,
) -> None:
    """LLT-7766: the VPN server takes over 0.0.0.0/0 while the meshnet exit node still holds it."""
    api, (alpha, beta) = setup_api(
        [(False, alpha_setup_params.ip_stack), (False, beta_setup_params.ip_stack)]
    )
    beta.set_peer_firewall_settings(
        alpha.id, allow_incoming_connections=True, allow_peer_traffic_routing=True
    )

    env = await setup_mesh_nodes_factory(
        [alpha_setup_params, beta_setup_params],
        provided_api=api,
        vpn=[ConnectionTag.DOCKER_VPN_1],
    )
    client_alpha, client_beta = env.clients
    connection_alpha, connection_beta = [conn.connection for conn in env.connections]

    await ping(connection_alpha, beta.ip_addresses[0])

    await client_beta.get_router().create_exit_node_route()
    await client_alpha.vpn.connect_to_exit_node(beta.public_key)
    assert await stun.get(connection_alpha, config.STUN_SERVER) == await stun.get(
        connection_beta, config.STUN_SERVER
    )

    await connect_to_vpn(client_alpha, connection_alpha)

    await ping(connection_alpha, beta.ip_addresses[0])


@pytest.mark.asyncio
@pytest.mark.parametrize("alpha_setup_params", ALPHA_SETUP_PARAMS)
@pytest.mark.parametrize("beta_setup_params", BETA_SETUP_PARAMS)
@pytest.mark.parametrize("gamma_setup_params", GAMMA_SETUP_PARAMS)
async def test_meshnet_ip_moved_to_new_peer(
    exit_stack: AsyncExitStack,
    alpha_setup_params: SetupParameters,
    beta_setup_params: SetupParameters,
    gamma_setup_params: SetupParameters,
) -> None:
    """LLT-7766: a new peer gets the meshnet IP which an existing peer still holds."""
    env = await start_alpha_with_stale_peer_ips(
        exit_stack,
        alpha_setup_params,
        beta_setup_params,
        gamma_setup_params,
        lambda beta, gamma: {beta.public_key: gamma.ip_addresses},
    )
    alpha, beta, gamma = env.nodes
    client_alpha, *_ = env.clients
    connection_alpha = env.connections[0].connection

    assert_peer_holds_ips_of(client_alpha, beta, gamma)

    await client_alpha.set_meshnet_config(env.api.get_meshnet_config(alpha.id))
    await client_alpha.events.wait_for_state_peer(
        gamma.public_key, [NodeState.CONNECTED]
    )

    await ping(connection_alpha, beta.ip_addresses[0])
    await ping(connection_alpha, gamma.ip_addresses[0])


@pytest.mark.asyncio
@pytest.mark.parametrize("alpha_setup_params", ALPHA_SETUP_PARAMS)
@pytest.mark.parametrize("beta_setup_params", BETA_SETUP_PARAMS)
@pytest.mark.parametrize("gamma_setup_params", GAMMA_SETUP_PARAMS)
async def test_meshnet_ips_swapped_between_peers(
    exit_stack: AsyncExitStack,
    alpha_setup_params: SetupParameters,
    beta_setup_params: SetupParameters,
    gamma_setup_params: SetupParameters,
) -> None:
    """LLT-7766: two existing peers get each other's meshnet IPs."""
    env = await start_alpha_with_stale_peer_ips(
        exit_stack,
        alpha_setup_params,
        beta_setup_params,
        gamma_setup_params,
        lambda beta, gamma: {
            beta.public_key: gamma.ip_addresses,
            gamma.public_key: beta.ip_addresses,
        },
    )
    alpha, beta, gamma = env.nodes
    client_alpha, *_ = env.clients
    connection_alpha = env.connections[0].connection

    assert_peer_holds_ips_of(client_alpha, beta, gamma)
    assert_peer_holds_ips_of(client_alpha, gamma, beta)

    await client_alpha.set_meshnet_config(env.api.get_meshnet_config(alpha.id))

    await ping(connection_alpha, beta.ip_addresses[0])
    await ping(connection_alpha, gamma.ip_addresses[0])


@pytest.mark.asyncio
@pytest.mark.parametrize("alpha_setup_params", ALPHA_SETUP_PARAMS)
@pytest.mark.parametrize("beta_setup_params", BETA_SETUP_PARAMS)
async def test_duplicate_allowed_ips_rejected_as_bad_config(
    alpha_setup_params: SetupParameters,  # pylint: disable=unused-argument
    beta_setup_params: SetupParameters,  # pylint: disable=unused-argument
    env_mesh: Environment,
) -> None:
    """LLT-7766: a rejected exit node is reported as BadConfig and libtelio keeps working."""
    _, beta = env_mesh.nodes
    client_alpha, *_ = env_mesh.clients
    connection_alpha = env_mesh.connections[0].connection
    wg_server = config.WG_SERVER

    await ping(connection_alpha, beta.ip_addresses[0])

    with pytest.raises(LibtelioError, match="BadConfig"):
        await client_alpha.get_proxy().connect_to_exit_node(
            public_key=str(wg_server["public_key"]),
            allowed_ips=API.get_allowed_ip_list(beta.ip_addresses),
            endpoint=f'{wg_server["ipv4"]}:{wg_server["port"]}',
        )

    await ping(connection_alpha, beta.ip_addresses[0])

    await connect_to_vpn(client_alpha, connection_alpha)

    await ping(connection_alpha, beta.ip_addresses[0])
