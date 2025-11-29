import asyncio
import pytest
from contextlib import AsyncExitStack
from tests import config, timeouts
from tests.helpers import SetupParameters, setup_mesh_nodes
from tests.mesh_api import API
from tests.telio import Client
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
from tests.utils.connection_util import (
    generate_connection_tracker_config,
    new_connection_with_conn_tracker,
)
from tests.utils.ping import ping


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
    alpha_setup_params: SetupParameters, beta_setup_params: SetupParameters
) -> None:
    async with AsyncExitStack() as exit_stack:
        env = await setup_mesh_nodes(
            exit_stack, [alpha_setup_params, beta_setup_params], prepare_vpn=True
        )

        _, beta = env.nodes
        client_alpha, _ = env.clients
        connection_alpha, _ = [conn.connection for conn in env.connections]

        await ping(connection_alpha, beta.ip_addresses[0])

        wg_server = config.WG_SERVER

        await client_alpha.connect_to_vpn(
            str(wg_server["ipv4"]), int(wg_server["port"]), str(wg_server["public_key"])
        )

        await ping(connection_alpha, beta.ip_addresses[0])

        await ping(connection_alpha, config.STUN_SERVER)

        public_ip = await stun.get(connection_alpha, config.STUN_SERVER)
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
    alpha_setup_params: SetupParameters, beta_setup_params: SetupParameters
) -> None:
    async with AsyncExitStack() as exit_stack:
        env = await setup_mesh_nodes(
            exit_stack, [alpha_setup_params, beta_setup_params], prepare_vpn=True
        )

        alpha, beta = env.nodes
        client_alpha, client_beta = env.clients
        connection_alpha, connection_beta = [
            conn.connection for conn in env.connections
        ]

        await ping(connection_alpha, beta.ip_addresses[0])

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

        await ping(connection_alpha, beta.ip_addresses[0])
        await ping(connection_alpha, config.STUN_SERVER)

        await ping(connection_beta, alpha.ip_addresses[0])
        await ping(connection_beta, config.STUN_SERVER)

        for connection in [connection_alpha, connection_beta]:
            public_ip = await stun.get(connection, config.STUN_SERVER)
            assert (
                public_ip == wg_server["ipv4"]
            ), f"wrong public IP when connected to VPN {public_ip}"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "alpha_connection_tag,adapter_type,public_ip",
    [
        pytest.param(
            ConnectionTag.DOCKER_CONE_CLIENT_1,
            TelioAdapterType.NEP_TUN,
            "10.0.254.1",
        ),
        pytest.param(
            ConnectionTag.DOCKER_CONE_CLIENT_1,
            TelioAdapterType.LINUX_NATIVE_TUN,
            "10.0.254.1",
            marks=pytest.mark.linux_native,
        ),
        pytest.param(
            ConnectionTag.VM_WINDOWS_1,
            TelioAdapterType.WINDOWS_NATIVE_TUN,
            "10.0.254.15",
            marks=pytest.mark.windows,
        ),
        pytest.param(
            ConnectionTag.VM_MAC,
            TelioAdapterType.NEP_TUN,
            "10.0.254.19",
            marks=pytest.mark.mac,
        ),
    ],
)
async def test_vpn_plus_mesh(
    alpha_connection_tag: ConnectionTag,
    adapter_type: TelioAdapterType,
    public_ip: str,
) -> None:
    async with AsyncExitStack() as exit_stack:
        api = API()

        (alpha, beta) = api.default_config_two_nodes()
        (connection_alpha, alpha_conn_tracker) = await exit_stack.enter_async_context(
            new_connection_with_conn_tracker(
                alpha_connection_tag,
                generate_connection_tracker_config(
                    alpha_connection_tag,
                    derp_1_limits=(1, 1),
                    vpn_1_limits=(1, 1),
                    stun_limits=(1, 1),
                ),
            )
        )
        (connection_beta, beta_conn_tracker) = await exit_stack.enter_async_context(
            new_connection_with_conn_tracker(
                ConnectionTag.DOCKER_CONE_CLIENT_2,
                generate_connection_tracker_config(
                    ConnectionTag.DOCKER_CONE_CLIENT_2,
                    derp_1_limits=(1, 1),
                ),
            )
        )

        await api.prepare_all_vpn_servers()

        ip = await stun.get(connection_alpha, config.STUN_SERVER)
        assert ip == public_ip, f"wrong public IP before connecting to VPN {ip}"

        client_alpha = await exit_stack.enter_async_context(
            Client(connection_alpha, alpha, adapter_type).run()
        )

        wg_server = config.WG_SERVER

        await client_alpha.connect_to_vpn(
            str(wg_server["ipv4"]), int(wg_server["port"]), str(wg_server["public_key"])
        )

        await ping(connection_alpha, config.PHOTO_ALBUM_IP)

        ip = await stun.get(connection_alpha, config.STUN_SERVER)
        assert ip == wg_server["ipv4"], f"wrong public IP when connected to VPN {ip}"

        await client_alpha.set_meshnet_config(api.get_meshnet_config(alpha.id))

        client_beta = await exit_stack.enter_async_context(
            Client(connection_beta, beta).run(api.get_meshnet_config(beta.id))
        )

        await asyncio.gather(
            client_alpha.wait_for_state_on_any_derp([RelayState.CONNECTED]),
            client_beta.wait_for_state_on_any_derp([RelayState.CONNECTED]),
        )
        await asyncio.gather(
            client_alpha.wait_for_state_peer(beta.public_key, [NodeState.CONNECTED]),
            client_beta.wait_for_state_peer(alpha.public_key, [NodeState.CONNECTED]),
        )

        await ping(connection_alpha, beta.ip_addresses[0])

        # Testing if the VPN node is not cleared after disabling meshnet. See LLT-4266 for more details.
        async with asyncio_util.run_async_context(
            client_alpha.wait_for_event_peer(
                beta.public_key, [NodeState.DISCONNECTED], list(PathType)
            )
        ) as event:
            await client_alpha.set_mesh_off()
            await event

        ip = await stun.get(connection_alpha, config.STUN_SERVER)
        assert ip == wg_server["ipv4"], f"wrong public IP when connected to VPN {ip}"

        assert await alpha_conn_tracker.find_conntracker_violations() is None
        assert await beta_conn_tracker.find_conntracker_violations() is None


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
            marks=[
                pytest.mark.linux_native,
            ],
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
            marks=[
                pytest.mark.windows,
            ],
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
    alpha_setup_params: SetupParameters, beta_setup_params: SetupParameters
) -> None:
    async with AsyncExitStack() as exit_stack:
        env = await setup_mesh_nodes(
            exit_stack, [alpha_setup_params, beta_setup_params], prepare_vpn=True
        )

        alpha, beta = env.nodes
        client_alpha, client_beta = env.clients
        connection_alpha, connection_beta = [
            conn.connection for conn in env.connections
        ]

        await ping(connection_alpha, beta.ip_addresses[0])
        await ping(connection_beta, alpha.ip_addresses[0])

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

        await ping(connection_alpha, beta.ip_addresses[0])
        await ping(connection_alpha, config.STUN_SERVER)

        await ping(connection_beta, alpha.ip_addresses[0])
        await ping(connection_beta, config.STUN_SERVER)

        for connection in [connection_alpha, connection_beta]:
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
    alpha_setup_params: SetupParameters,
    beta_setup_params: SetupParameters,
    gamma_setup_params: SetupParameters,
) -> None:
    async with AsyncExitStack() as exit_stack:
        env = await setup_mesh_nodes(
            exit_stack,
            [alpha_setup_params, beta_setup_params, gamma_setup_params],
            prepare_vpn=True,
        )

        connection_alpha, connection_beta, connection_gamma = [
            conn.connection for conn in env.connections
        ]
        client_alpha, client_beta, client_gamma = env.clients
        alpha, beta, gamma = env.nodes

        await ping(connection_alpha, beta.ip_addresses[0])
        await ping(connection_alpha, gamma.ip_addresses[0])

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

        await ping(connection_alpha, beta.ip_addresses[0])
        await ping(connection_alpha, gamma.ip_addresses[0])
        await ping(connection_alpha, config.STUN_SERVER)

        await ping(connection_beta, alpha.ip_addresses[0])
        await ping(connection_beta, config.STUN_SERVER)

        await ping(connection_gamma, alpha.ip_addresses[0])
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
