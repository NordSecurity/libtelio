import asyncio
import config
import pytest
import timeouts
from contextlib import AsyncExitStack
from helpers import (
    setup_connections,
    setup_environment,
    setup_mesh_nodes,
    SetupParameters,
)
from utils import stun
from utils.asyncio_util import run_async_contexts
from utils.bindings import (
    features_with_endpoint_providers,
    EndpointProvider,
    PathType,
    TelioAdapterType,
    NodeState,
    RelayState,
)
from utils.connection import TargetOS, ConnectionTag
from utils.ping import ping


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
            "10.0.254.7",
            "10.0.254.8",
            marks=pytest.mark.windows,
        ),
        pytest.param(
            ConnectionTag.VM_MAC,
            "10.0.254.7",
            "10.0.254.8",
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
