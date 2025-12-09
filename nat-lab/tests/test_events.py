import asyncio
import pytest
from contextlib import AsyncExitStack
from deepdiff import DeepDiff
from tests import config, timeouts
from tests.helpers import (
    SetupParameters,
    setup_environment,
    setup_mesh_nodes,
    setup_api,
)
from tests.mesh_api import API
from tests.telio import Client
from tests.utils import stun
from tests.utils.bindings import (
    features_with_endpoint_providers,
    default_features,
    EndpointProvider,
    PathType,
    TelioNode,
    NodeState,
    RelayState,
    telio_node,
    TelioAdapterType,
)
from tests.utils.connection import ConnectionTag
from tests.utils.connection_util import (
    generate_connection_tracker_config,
    new_connection_with_conn_tracker,
)
from tests.utils.ping import ping
from tests.utils.router import IPStack
from tests.utils.testing import log_test_passed
from typing import Optional


def node_diff(left: TelioNode, right: TelioNode) -> Optional[str]:
    exclude_paths = []
    for attr in ["link_state", "endpoint", "hostname", "nickname"]:
        if getattr(left, attr) is None or getattr(right, attr) is None:
            exclude_paths.append(f"root['{attr}']")

    diff = DeepDiff(
        left.__dict__,
        right.__dict__,
        exclude_paths=exclude_paths,
        ignore_order=True,
        report_repetition=True,
        verbose_level=2,
    )
    if not diff:
        return None

    return diff.pretty()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "alpha_setup_params",
    [
        pytest.param(
            SetupParameters(
                connection_tag=ConnectionTag.DOCKER_CONE_CLIENT_1,
                adapter_type_override=TelioAdapterType.NEP_TUN,
                connection_tracker_config=generate_connection_tracker_config(
                    ConnectionTag.DOCKER_CONE_CLIENT_1,
                    derp_1_limits=(1, 1),
                ),
            ),
            id="a_lne",
        ),
        pytest.param(
            SetupParameters(
                connection_tag=ConnectionTag.DOCKER_CONE_CLIENT_1,
                adapter_type_override=TelioAdapterType.LINUX_NATIVE_TUN,
                connection_tracker_config=generate_connection_tracker_config(
                    ConnectionTag.DOCKER_CONE_CLIENT_1,
                    derp_1_limits=(1, 1),
                ),
            ),
            marks=pytest.mark.linux_native,
            id="a_lna",
        ),
        pytest.param(
            SetupParameters(
                connection_tag=ConnectionTag.VM_WINDOWS_1,
                adapter_type_override=TelioAdapterType.WINDOWS_NATIVE_TUN,
                connection_tracker_config=generate_connection_tracker_config(
                    ConnectionTag.VM_WINDOWS_1,
                    derp_1_limits=(1, 1),
                ),
            ),
            marks=pytest.mark.windows,
            id="a_wna",
        ),
        pytest.param(
            SetupParameters(
                connection_tag=ConnectionTag.VM_MAC,
                adapter_type_override=TelioAdapterType.NEP_TUN,
                connection_tracker_config=generate_connection_tracker_config(
                    ConnectionTag.VM_MAC,
                    derp_1_limits=(1, 1),
                ),
            ),
            marks=pytest.mark.mac,
            id="a_mac",
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
                    derp_1_limits=(1, 1),
                ),
            ),
            id="b",
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
        assert (
            node_diff(
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
            is None
        )

        alpha_node_state = client_beta.get_node_state(alpha.public_key)
        assert alpha_node_state
        assert (
            node_diff(
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
            is None
        )

        api.remove(beta.id)

        await client_alpha.set_meshnet_config(api.get_meshnet_config(alpha.id))

        await client_alpha.wait_for_state_peer(
            beta.public_key, [NodeState.DISCONNECTED], [PathType.DIRECT]
        )

        with pytest.raises(asyncio.TimeoutError):
            await ping(connection_alpha, beta.ip_addresses[0], 5)

        beta_node_state = client_alpha.get_node_state(beta.public_key)
        assert beta_node_state
        assert (
            node_diff(
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
            is None
        )
        log_test_passed()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "alpha_setup_params, alpha_public_ip",
    [
        pytest.param(
            SetupParameters(
                connection_tag=ConnectionTag.DOCKER_CONE_CLIENT_1,
                adapter_type_override=TelioAdapterType.NEP_TUN,
                connection_tracker_config=generate_connection_tracker_config(
                    ConnectionTag.DOCKER_CONE_CLIENT_1,
                    vpn_1_limits=(1, 1),
                    stun_limits=(1, 2),
                ),
                is_meshnet=False,
            ),
            "10.0.254.1",
            id="a_lne",
        ),
        pytest.param(
            SetupParameters(
                connection_tag=ConnectionTag.DOCKER_CONE_CLIENT_1,
                adapter_type_override=TelioAdapterType.LINUX_NATIVE_TUN,
                connection_tracker_config=generate_connection_tracker_config(
                    ConnectionTag.DOCKER_CONE_CLIENT_1,
                    vpn_1_limits=(1, 1),
                    stun_limits=(1, 2),
                ),
                is_meshnet=False,
            ),
            "10.0.254.1",
            marks=pytest.mark.linux_native,
            id="a_lna",
        ),
        pytest.param(
            SetupParameters(
                connection_tag=ConnectionTag.VM_WINDOWS_1,
                adapter_type_override=TelioAdapterType.WINDOWS_NATIVE_TUN,
                connection_tracker_config=generate_connection_tracker_config(
                    ConnectionTag.VM_WINDOWS_1,
                    vpn_1_limits=(1, 1),
                    stun_limits=(1, 2),
                ),
                is_meshnet=False,
            ),
            "10.0.254.15",
            marks=[
                pytest.mark.windows,
            ],
            id="a_wna",
        ),
        pytest.param(
            SetupParameters(
                connection_tag=ConnectionTag.VM_MAC,
                adapter_type_override=TelioAdapterType.NEP_TUN,
                connection_tracker_config=generate_connection_tracker_config(
                    ConnectionTag.VM_MAC,
                    vpn_1_limits=(1, 1),
                    stun_limits=(1, 2),
                ),
                is_meshnet=False,
            ),
            "10.0.254.19",
            marks=pytest.mark.mac,
            id="a_mac",
        ),
    ],
)
async def test_event_content_vpn_connection(
    alpha_setup_params: SetupParameters, alpha_public_ip: str
) -> None:
    async with AsyncExitStack() as exit_stack:
        env = await exit_stack.enter_async_context(
            setup_environment(exit_stack, [alpha_setup_params], prepare_vpn=True)
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
        assert (
            node_diff(
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
                    allow_multicast=False,
                    peer_allows_multicast=False,
                ),
            )
            is None
        )

        ip = await stun.get(connection, config.STUN_SERVER)
        assert ip == wg_server["ipv4"], f"wrong public IP when connected to VPN {ip}"

        await client_alpha.disconnect_from_vpn(str(wg_server["public_key"]))

        ip = await stun.get(connection, config.STUN_SERVER)
        assert ip == alpha_public_ip, f"wrong public IP before connecting to VPN {ip}"

        wg_node_state = client_alpha.get_node_state(str(wg_server["public_key"]))
        assert wg_node_state
        assert (
            node_diff(
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
                    allow_multicast=False,
                    peer_allows_multicast=False,
                ),
            )
            is None
        )
        log_test_passed()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "alpha_setup_params",
    [
        pytest.param(
            SetupParameters(
                connection_tag=ConnectionTag.DOCKER_CONE_CLIENT_1,
                adapter_type_override=TelioAdapterType.NEP_TUN,
                connection_tracker_config=generate_connection_tracker_config(
                    ConnectionTag.DOCKER_CONE_CLIENT_1,
                    derp_1_limits=(1, 1),
                ),
            ),
            id="a_lne",
        ),
        pytest.param(
            SetupParameters(
                connection_tag=ConnectionTag.DOCKER_CONE_CLIENT_1,
                adapter_type_override=TelioAdapterType.LINUX_NATIVE_TUN,
                connection_tracker_config=generate_connection_tracker_config(
                    ConnectionTag.DOCKER_CONE_CLIENT_1,
                    derp_1_limits=(1, 1),
                ),
            ),
            marks=pytest.mark.linux_native,
            id="a_lna",
        ),
        pytest.param(
            SetupParameters(
                connection_tag=ConnectionTag.VM_WINDOWS_1,
                adapter_type_override=TelioAdapterType.WINDOWS_NATIVE_TUN,
                connection_tracker_config=generate_connection_tracker_config(
                    ConnectionTag.VM_WINDOWS_1,
                    derp_1_limits=(1, 1),
                ),
            ),
            marks=pytest.mark.windows,
            id="a_wna",
        ),
        pytest.param(
            SetupParameters(
                connection_tag=ConnectionTag.VM_MAC,
                adapter_type_override=TelioAdapterType.NEP_TUN,
                connection_tracker_config=generate_connection_tracker_config(
                    ConnectionTag.VM_MAC,
                    derp_1_limits=(1, 1),
                ),
            ),
            marks=pytest.mark.mac,
            id="a_mac",
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
                    derp_1_limits=(1, 1),
                    stun_limits=(1, 2),
                ),
                features=default_features(enable_firewall_exclusion_range="10.0.0.0/8"),
            ),
            id="b",
        ),
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
        beta.set_peer_firewall_settings(
            alpha.id, allow_incoming_connections=True, allow_peer_traffic_routing=True
        )
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
        assert (
            node_diff(
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
            is None
        )

        await client_beta.get_router().create_exit_node_route()

        await client_alpha.connect_to_exit_node(beta.public_key)

        ip_alpha = await stun.get(connection_alpha, config.STUN_SERVER)
        ip_beta = await stun.get(connection_beta, config.STUN_SERVER)

        assert ip_alpha == ip_beta

        beta_node_state = client_alpha.get_node_state(beta.public_key)
        assert beta_node_state
        assert (
            node_diff(
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
            is None
        )
        log_test_passed()


@pytest.mark.asyncio
@pytest.mark.timeout(timeouts.TEST_EVENT_CONTENT_MESHNET_NODE_UPGRADE_DIRECT_TIMEOUT)
@pytest.mark.parametrize(
    "alpha_setup_params, alpha_public_ip",
    [
        pytest.param(
            SetupParameters(
                connection_tag=ConnectionTag.DOCKER_CONE_CLIENT_1,
                adapter_type_override=TelioAdapterType.NEP_TUN,
                connection_tracker_config=generate_connection_tracker_config(
                    ConnectionTag.DOCKER_CONE_CLIENT_1,
                    derp_1_limits=(1, 1),
                ),
                features=features_with_endpoint_providers([EndpointProvider.STUN]),
            ),
            "10.0.254.1",
            id="a_lne",
        ),
        pytest.param(
            SetupParameters(
                connection_tag=ConnectionTag.DOCKER_CONE_CLIENT_1,
                adapter_type_override=TelioAdapterType.LINUX_NATIVE_TUN,
                connection_tracker_config=generate_connection_tracker_config(
                    ConnectionTag.DOCKER_CONE_CLIENT_1,
                    derp_1_limits=(1, 1),
                ),
                features=features_with_endpoint_providers([EndpointProvider.STUN]),
            ),
            "10.0.254.1",
            marks=pytest.mark.linux_native,
            id="a_lna",
        ),
        pytest.param(
            SetupParameters(
                connection_tag=ConnectionTag.VM_WINDOWS_1,
                adapter_type_override=TelioAdapterType.WINDOWS_NATIVE_TUN,
                connection_tracker_config=generate_connection_tracker_config(
                    ConnectionTag.VM_WINDOWS_1,
                    derp_1_limits=(1, 1),
                ),
                features=features_with_endpoint_providers([EndpointProvider.STUN]),
            ),
            "10.0.254.15",
            marks=pytest.mark.windows,
            id="a_wna",
        ),
        pytest.param(
            SetupParameters(
                connection_tag=ConnectionTag.VM_MAC,
                adapter_type_override=TelioAdapterType.NEP_TUN,
                connection_tracker_config=generate_connection_tracker_config(
                    ConnectionTag.VM_MAC,
                    derp_1_limits=(1, 1),
                ),
                features=features_with_endpoint_providers([EndpointProvider.STUN]),
            ),
            "10.0.254.19",
            marks=[pytest.mark.mac],
            id="a_mac",
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
                    derp_1_limits=(1, 2),
                ),
            ),
            "10.0.254.2",
            id="b",
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
            assert (
                node_diff(
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
                is None
            )
            assert (
                beta_node_state.endpoint
                and beta_public_ip not in beta_node_state.endpoint
            )

            alpha_node_state = client_beta.get_node_state(alpha.public_key)
            assert alpha_node_state
            assert (
                node_diff(
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
                is None
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
        assert (
            node_diff(
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
            is None
        )
        assert beta_node_state.endpoint and beta_public_ip in beta_node_state.endpoint

        alpha_node_state = client_beta.get_node_state(alpha.public_key)
        assert alpha_node_state
        assert (
            node_diff(
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
            is None
        )
        assert (
            alpha_node_state.endpoint and alpha_public_ip in alpha_node_state.endpoint
        )

        assert await alpha_conn_tracker.find_conntracker_violations() is None
        assert await beta_conn_tracker.find_conntracker_violations() is None
        log_test_passed()
