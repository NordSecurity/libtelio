import asyncio
import pytest
from tests import config, timeouts
from tests.helpers import SetupParameters
from tests.utils import stun, asyncio_util
from tests.utils.bindings import (
    features_with_endpoint_providers,
    EndpointProvider,
    TelioAdapterType,
    PathType,
    RelayState,
    NodeState,
)
from tests.utils.connection import ConnectionTag
from tests.utils.connection_util import generate_connection_tracker_config
from tests.utils.ping import ping

pytest_plugins = ["tests.helpers_fixtures"]


# Module-level override — all tests in this file get VPN_1
@pytest.fixture(name="vpn_tags")
def _vpn_tags() -> list:
    return [ConnectionTag.DOCKER_VPN_1]


# Marks in-tunnel stack only, exiting only through IPv4
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
                    vpn_1_limits=(1, 1),
                ),
            )
        ),
        pytest.param(
            SetupParameters(
                connection_tag=ConnectionTag.DOCKER_CONE_CLIENT_1,
                adapter_type_override=TelioAdapterType.LINUX_NATIVE_TUN,
                connection_tracker_config=generate_connection_tracker_config(
                    ConnectionTag.DOCKER_CONE_CLIENT_1,
                    derp_1_limits=(1, 1),
                    vpn_1_limits=(1, 1),
                ),
            ),
            marks=pytest.mark.linux_native,
        ),
        pytest.param(
            SetupParameters(
                connection_tag=ConnectionTag.VM_WINDOWS_1,
                adapter_type_override=TelioAdapterType.WINDOWS_NATIVE_TUN,
                connection_tracker_config=generate_connection_tracker_config(
                    ConnectionTag.VM_WINDOWS_1,
                    derp_1_limits=(1, 1),
                    vpn_1_limits=(1, 1),
                ),
            ),
            marks=pytest.mark.windows,
        ),
        pytest.param(
            SetupParameters(
                connection_tag=ConnectionTag.VM_MAC,
                adapter_type_override=TelioAdapterType.NEP_TUN,
                connection_tracker_config=generate_connection_tracker_config(
                    ConnectionTag.VM_MAC,
                    derp_1_limits=(1, 1),
                    vpn_1_limits=(1, 1),
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
                    derp_1_limits=(1, 1),
                ),
            )
        )
    ],
)
async def test_mesh_plus_vpn_one_peer(
    alpha_setup_params: SetupParameters,  # pylint: disable=unused-argument
    beta_setup_params: SetupParameters,  # pylint: disable=unused-argument
    env_mesh,
) -> None:
    beta_node, alpha_client, alpha_conn = (
        env_mesh.nodes[1],
        env_mesh.clients[0],
        env_mesh.connections[0].connection,
    )

    await ping(alpha_conn, beta_node.ip_addresses[0])

    wg_server = config.WG_SERVER

    await alpha_client.connect_to_vpn(
        str(wg_server["ipv4"]), int(wg_server["port"]), str(wg_server["public_key"])
    )

    await ping(alpha_conn, beta_node.ip_addresses[0])
    await ping(alpha_conn, config.STUN_SERVER)

    public_ip = await stun.get(alpha_conn, config.STUN_SERVER)
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
                adapter_type_override=TelioAdapterType.NEP_TUN,
                connection_tracker_config=generate_connection_tracker_config(
                    ConnectionTag.DOCKER_CONE_CLIENT_1,
                    derp_1_limits=(1, 1),
                    vpn_1_limits=(1, 1),
                ),
            )
        ),
        pytest.param(
            SetupParameters(
                connection_tag=ConnectionTag.DOCKER_CONE_CLIENT_1,
                adapter_type_override=TelioAdapterType.LINUX_NATIVE_TUN,
                connection_tracker_config=generate_connection_tracker_config(
                    ConnectionTag.DOCKER_CONE_CLIENT_1,
                    derp_1_limits=(1, 1),
                    vpn_1_limits=(1, 1),
                ),
            ),
            marks=pytest.mark.linux_native,
        ),
        pytest.param(
            SetupParameters(
                connection_tag=ConnectionTag.VM_WINDOWS_1,
                adapter_type_override=TelioAdapterType.WINDOWS_NATIVE_TUN,
                connection_tracker_config=generate_connection_tracker_config(
                    ConnectionTag.VM_WINDOWS_1,
                    derp_1_limits=(1, 1),
                    vpn_1_limits=(1, 1),
                ),
            ),
            marks=pytest.mark.windows,
        ),
        pytest.param(
            SetupParameters(
                connection_tag=ConnectionTag.VM_MAC,
                adapter_type_override=TelioAdapterType.NEP_TUN,
                connection_tracker_config=generate_connection_tracker_config(
                    ConnectionTag.VM_MAC,
                    derp_1_limits=(1, 1),
                    vpn_1_limits=(1, 1),
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
                    derp_1_limits=(1, 1),
                    vpn_1_limits=(1, 1),
                ),
            )
        )
    ],
)
async def test_mesh_plus_vpn_both_peers(
    alpha_setup_params: SetupParameters,  # pylint: disable=unused-argument
    beta_setup_params: SetupParameters,  # pylint: disable=unused-argument
    env_mesh,
) -> None:
    alpha_node, beta_node = env_mesh.nodes[0], env_mesh.nodes[1]
    alpha_client, beta_client = env_mesh.clients[0], env_mesh.clients[1]
    alpha_conn, beta_conn = (
        env_mesh.connections[0].connection,
        env_mesh.connections[1].connection,
    )

    await ping(alpha_conn, beta_node.ip_addresses[0])

    wg_server = config.WG_SERVER

    await asyncio.gather(
        alpha_client.connect_to_vpn(
            str(wg_server["ipv4"]),
            int(wg_server["port"]),
            str(wg_server["public_key"]),
        ),
        beta_client.connect_to_vpn(
            str(wg_server["ipv4"]),
            int(wg_server["port"]),
            str(wg_server["public_key"]),
        ),
    )

    await ping(alpha_conn, beta_node.ip_addresses[0])
    await ping(alpha_conn, config.STUN_SERVER)

    await ping(beta_conn, alpha_node.ip_addresses[0])
    await ping(beta_conn, config.STUN_SERVER)

    for connection in [alpha_conn, beta_conn]:
        public_ip = await stun.get(connection, config.STUN_SERVER)
        assert (
            public_ip == wg_server["ipv4"]
        ), f"wrong public IP when connected to VPN {public_ip}"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "alpha_setup_params, public_ip",
    [
        pytest.param(
            SetupParameters(
                connection_tag=ConnectionTag.DOCKER_CONE_CLIENT_1,
                adapter_type_override=TelioAdapterType.NEP_TUN,
                connection_tracker_config=generate_connection_tracker_config(
                    ConnectionTag.DOCKER_CONE_CLIENT_1,
                    derp_1_limits=(1, 1),
                    vpn_1_limits=(1, 1),
                    stun_limits=(1, 1),
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
                    derp_1_limits=(1, 1),
                    vpn_1_limits=(1, 1),
                    stun_limits=(1, 1),
                ),
                is_meshnet=False,
            ),
            "10.0.254.1",
            marks=pytest.mark.linux_native,
        ),
        pytest.param(
            SetupParameters(
                connection_tag=ConnectionTag.VM_WINDOWS_1,
                adapter_type_override=TelioAdapterType.WINDOWS_NATIVE_TUN,
                connection_tracker_config=generate_connection_tracker_config(
                    ConnectionTag.VM_WINDOWS_1,
                    derp_1_limits=(1, 1),
                    vpn_1_limits=(1, 1),
                    stun_limits=(1, 1),
                ),
                is_meshnet=False,
            ),
            "10.0.254.15",
            marks=pytest.mark.windows,
        ),
        pytest.param(
            SetupParameters(
                connection_tag=ConnectionTag.VM_MAC,
                adapter_type_override=TelioAdapterType.NEP_TUN,
                connection_tracker_config=generate_connection_tracker_config(
                    ConnectionTag.VM_MAC,
                    derp_1_limits=(1, 1),
                    vpn_1_limits=(1, 1),
                    stun_limits=(1, 1),
                ),
                is_meshnet=False,
            ),
            "10.0.254.19",
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
                    derp_1_limits=(1, 1),
                ),
            )
        )
    ],
)
async def test_vpn_plus_mesh(
    alpha_setup_params: SetupParameters,  # pylint: disable=unused-argument
    beta_setup_params: SetupParameters,  # pylint: disable=unused-argument
    public_ip: str,
    env,
) -> None:
    alpha_node, beta_node = env.nodes
    client_alpha, client_beta = env.clients
    connection_alpha = env.connections[0].connection
    api = env.api

    ip = await stun.get(connection_alpha, config.STUN_SERVER)
    assert ip == public_ip, f"wrong public IP before connecting to VPN {ip}"

    wg_server = config.WG_SERVER

    await client_alpha.connect_to_vpn(
        str(wg_server["ipv4"]), int(wg_server["port"]), str(wg_server["public_key"])
    )

    await ping(connection_alpha, config.PHOTO_ALBUM_IP)

    ip = await stun.get(connection_alpha, config.STUN_SERVER)
    assert ip == wg_server["ipv4"], f"wrong public IP when connected to VPN {ip}"

    await client_alpha.set_meshnet_config(api.get_meshnet_config(alpha_node.id))

    await asyncio.gather(
        client_alpha.wait_for_state_on_any_derp([RelayState.CONNECTED]),
        client_beta.wait_for_state_on_any_derp([RelayState.CONNECTED]),
    )
    await asyncio.gather(
        client_alpha.wait_for_state_peer(beta_node.public_key, [NodeState.CONNECTED]),
        client_beta.wait_for_state_peer(alpha_node.public_key, [NodeState.CONNECTED]),
    )

    await ping(connection_alpha, beta_node.ip_addresses[0])

    # Testing if the VPN node is not cleared after disabling meshnet. See LLT-4266 for more details.
    async with asyncio_util.run_async_context(
        client_alpha.wait_for_event_peer(
            beta_node.public_key, [NodeState.DISCONNECTED], list(PathType)
        )
    ) as event:
        await client_alpha.set_mesh_off()
        await event

    ip = await stun.get(connection_alpha, config.STUN_SERVER)
    assert ip == wg_server["ipv4"], f"wrong public IP when connected to VPN {ip}"


@pytest.mark.asyncio
@pytest.mark.timeout(timeouts.TEST_VPN_PLUS_MESH_OVER_DIRECT_TIMEOUT)
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
                    vpn_1_limits=(1, 1),
                ),
                features=features_with_endpoint_providers(
                    [EndpointProvider.LOCAL, EndpointProvider.STUN]
                ),
            ),
        ),
        pytest.param(
            SetupParameters(
                connection_tag=ConnectionTag.DOCKER_CONE_CLIENT_1,
                adapter_type_override=TelioAdapterType.LINUX_NATIVE_TUN,
                connection_tracker_config=generate_connection_tracker_config(
                    ConnectionTag.DOCKER_CONE_CLIENT_1,
                    derp_1_limits=(1, 1),
                    vpn_1_limits=(1, 1),
                ),
                features=features_with_endpoint_providers(
                    [EndpointProvider.LOCAL, EndpointProvider.STUN]
                ),
            ),
            marks=[pytest.mark.linux_native],
        ),
        pytest.param(
            SetupParameters(
                connection_tag=ConnectionTag.VM_WINDOWS_1,
                adapter_type_override=TelioAdapterType.WINDOWS_NATIVE_TUN,
                connection_tracker_config=generate_connection_tracker_config(
                    ConnectionTag.VM_WINDOWS_1,
                    derp_1_limits=(1, 1),
                    vpn_1_limits=(1, 1),
                ),
                features=features_with_endpoint_providers(
                    [EndpointProvider.LOCAL, EndpointProvider.STUN]
                ),
            ),
            marks=[pytest.mark.windows],
        ),
        pytest.param(
            SetupParameters(
                connection_tag=ConnectionTag.VM_MAC,
                adapter_type_override=TelioAdapterType.NEP_TUN,
                connection_tracker_config=generate_connection_tracker_config(
                    ConnectionTag.VM_MAC,
                    derp_1_limits=(1, 1),
                    vpn_1_limits=(1, 1),
                ),
                features=features_with_endpoint_providers(
                    [EndpointProvider.LOCAL, EndpointProvider.STUN]
                ),
            ),
            marks=[pytest.mark.mac],
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
                    vpn_1_limits=(1, 1),
                ),
                features=features_with_endpoint_providers(
                    [EndpointProvider.LOCAL, EndpointProvider.STUN]
                ),
            )
        )
    ],
)
async def test_vpn_plus_mesh_over_direct(
    alpha_setup_params: SetupParameters,  # pylint: disable=unused-argument
    beta_setup_params: SetupParameters,  # pylint: disable=unused-argument
    env_mesh,
) -> None:
    alpha_node, beta_node = env_mesh.nodes[0], env_mesh.nodes[1]
    alpha_client, beta_client = env_mesh.clients[0], env_mesh.clients[1]
    alpha_conn, beta_conn = (
        env_mesh.connections[0].connection,
        env_mesh.connections[1].connection,
    )

    await ping(alpha_conn, beta_node.ip_addresses[0])
    await ping(beta_conn, alpha_node.ip_addresses[0])

    wg_server = config.WG_SERVER

    await asyncio.gather(
        alpha_client.connect_to_vpn(
            str(wg_server["ipv4"]),
            int(wg_server["port"]),
            str(wg_server["public_key"]),
        ),
        beta_client.connect_to_vpn(
            str(wg_server["ipv4"]),
            int(wg_server["port"]),
            str(wg_server["public_key"]),
        ),
    )

    await ping(alpha_conn, beta_node.ip_addresses[0])
    await ping(alpha_conn, config.STUN_SERVER)

    await ping(beta_conn, alpha_node.ip_addresses[0])
    await ping(beta_conn, config.STUN_SERVER)

    for connection in [alpha_conn, beta_conn]:
        public_ip = await stun.get(connection, config.STUN_SERVER)
        assert (
            public_ip == wg_server["ipv4"]
        ), f"wrong public IP when connected to VPN {public_ip}"

    # LLT-5532: To be cleaned up...
    alpha_client.allow_errors(
        ["telio_proxy::proxy.*Unable to send. WG Address not available"]
    )
    beta_client.allow_errors(
        ["telio_proxy::proxy.*Unable to send. WG Address not available"]
    )


class TestThreeNode:
    @pytest.mark.asyncio
    @pytest.mark.timeout(
        timeouts.TEST_VPN_PLUS_MESH_OVER_DIFFERENT_CONNECTION_TYPES_TIMEOUT
    )
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
                        vpn_1_limits=(1, 1),
                    ),
                    features=features_with_endpoint_providers(
                        [EndpointProvider.LOCAL, EndpointProvider.STUN]
                    ),
                )
            ),
            pytest.param(
                SetupParameters(
                    connection_tag=ConnectionTag.DOCKER_CONE_CLIENT_1,
                    adapter_type_override=TelioAdapterType.LINUX_NATIVE_TUN,
                    connection_tracker_config=generate_connection_tracker_config(
                        ConnectionTag.DOCKER_CONE_CLIENT_1,
                        derp_1_limits=(1, 1),
                        vpn_1_limits=(1, 1),
                    ),
                    features=features_with_endpoint_providers(
                        [EndpointProvider.LOCAL, EndpointProvider.STUN]
                    ),
                ),
                marks=pytest.mark.linux_native,
            ),
            pytest.param(
                SetupParameters(
                    connection_tag=ConnectionTag.VM_WINDOWS_1,
                    adapter_type_override=TelioAdapterType.WINDOWS_NATIVE_TUN,
                    connection_tracker_config=generate_connection_tracker_config(
                        ConnectionTag.VM_WINDOWS_1,
                        derp_1_limits=(1, 1),
                        vpn_1_limits=(1, 1),
                    ),
                    features=features_with_endpoint_providers(
                        [EndpointProvider.LOCAL, EndpointProvider.STUN]
                    ),
                ),
                marks=pytest.mark.windows,
            ),
            pytest.param(
                SetupParameters(
                    connection_tag=ConnectionTag.VM_MAC,
                    adapter_type_override=TelioAdapterType.NEP_TUN,
                    connection_tracker_config=generate_connection_tracker_config(
                        ConnectionTag.VM_MAC,
                        derp_1_limits=(1, 1),
                        vpn_1_limits=(1, 1),
                    ),
                    features=features_with_endpoint_providers(
                        [EndpointProvider.LOCAL, EndpointProvider.STUN]
                    ),
                ),
                marks=[pytest.mark.mac],
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
                        vpn_1_limits=(1, 1),
                    ),
                    features=features_with_endpoint_providers(
                        [EndpointProvider.LOCAL, EndpointProvider.STUN]
                    ),
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
                        derp_1_limits=(1, 1),
                        vpn_1_limits=(1, 1),
                    ),
                )
            )
        ],
    )
    async def test_vpn_plus_mesh_over_different_connection_types(
        self,
        alpha_setup_params: SetupParameters,  # pylint: disable=unused-argument
        beta_setup_params: SetupParameters,  # pylint: disable=unused-argument
        gamma_setup_params: SetupParameters,  # pylint: disable=unused-argument
        env_mesh,
    ) -> None:
        alpha_node, beta_node, gamma_node = env_mesh.nodes
        client_alpha, client_beta, client_gamma = env_mesh.clients
        connection_alpha, connection_beta, connection_gamma = [
            conn.connection for conn in env_mesh.connections
        ]

        await ping(connection_alpha, beta_node.ip_addresses[0])
        await ping(connection_alpha, gamma_node.ip_addresses[0])

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

        await ping(connection_alpha, beta_node.ip_addresses[0])
        await ping(connection_alpha, gamma_node.ip_addresses[0])
        await ping(connection_alpha, config.STUN_SERVER)

        await ping(connection_beta, alpha_node.ip_addresses[0])
        await ping(connection_beta, config.STUN_SERVER)

        await ping(connection_gamma, alpha_node.ip_addresses[0])
        await ping(connection_gamma, config.STUN_SERVER)

        for connection in [connection_alpha, connection_beta, connection_gamma]:
            public_ip = await stun.get(connection, config.STUN_SERVER)
            assert (
                public_ip == wg_server["ipv4"]
            ), f"wrong public IP when connected to VPN {public_ip}"

        # LLT-5532: To be cleaned up...
        client_alpha.allow_errors(
            ["telio_proxy::proxy.*Unable to send. WG Address not available"]
        )
        client_beta.allow_errors(
            ["telio_proxy::proxy.*Unable to send. WG Address not available"]
        )
