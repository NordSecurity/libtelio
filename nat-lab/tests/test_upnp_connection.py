import asyncio
import pytest
from contextlib import AsyncExitStack
from helpers import SetupParameters, setup_mesh_nodes, setup_environment
from telio import AdapterType, PathType, State
from utils.asyncio_util import run_async_context
from utils.bindings import features_with_endpoint_providers, EndpointProvider
from utils.connection_util import ConnectionTag
from utils.ping import ping
from utils.router import new_router, IPStack


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "alpha_setup_params",
    [
        SetupParameters(
            connection_tag=ConnectionTag.DOCKER_UPNP_CLIENT_1,
            adapter_type=AdapterType.BoringTun,
            features=features_with_endpoint_providers([EndpointProvider.UPNP]),
        ),
    ],
)
@pytest.mark.parametrize(
    "beta_setup_params",
    [
        SetupParameters(
            connection_tag=ConnectionTag.DOCKER_UPNP_CLIENT_2,
            adapter_type=AdapterType.BoringTun,
            features=features_with_endpoint_providers([EndpointProvider.UPNP]),
        ),
    ],
)
async def test_upnp_route_removed(
    alpha_setup_params: SetupParameters, beta_setup_params: SetupParameters
) -> None:
    async with AsyncExitStack() as exit_stack:
        env = await setup_mesh_nodes(
            exit_stack, [alpha_setup_params, beta_setup_params]
        )
        alpha, beta = env.nodes
        alpha_conn, beta_conn = env.connections
        alpha_client, beta_client = env.clients

        assert alpha_conn.gw_connection
        assert beta_conn.gw_connection

        alpha_gw_router = new_router(alpha_conn.gw_connection, IPStack.IPv4v6)
        beta_gw_router = new_router(beta_conn.gw_connection, IPStack.IPv4v6)

        # Shutoff Upnpd on both gateways to wipe out all upnp created external
        # routes, this also requires to wipe-out the contrack list
        async with AsyncExitStack() as temp_exit_stack:
            await temp_exit_stack.enter_async_context(alpha_gw_router.reset_upnpd())
            await temp_exit_stack.enter_async_context(beta_gw_router.reset_upnpd())
            task = await temp_exit_stack.enter_async_context(
                run_async_context(
                    alpha_client.wait_for_event_peer(beta.public_key, [State.Connected])
                )
            )
            try:
                await ping(alpha_conn.connection, beta.ip_addresses[0], 15)
            except asyncio.TimeoutError:
                pass
            else:
                # if no timeout exception happens, this means, that peers connected through relay
                # faster than we expected, but if no relay event occurs, this means, that something
                # else was wrong, so we assert
                await asyncio.wait_for(task, 1)

        await asyncio.gather(
            alpha_client.wait_for_event_peer(
                beta.public_key, [State.Connected], [PathType.Direct]
            ),
            beta_client.wait_for_event_peer(
                alpha.public_key, [State.Connected], [PathType.Direct]
            ),
        )

        await ping(beta_conn.connection, alpha.ip_addresses[0])
        await ping(alpha_conn.connection, beta.ip_addresses[0])

        # LLT-5532: To be cleaned up...
        alpha_client.allow_errors(
            ["telio_proxy::proxy.*Unable to send. WG Address not available"]
        )
        beta_client.allow_errors(
            ["telio_proxy::proxy.*Unable to send. WG Address not available"]
        )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "alpha_setup_params",
    [
        pytest.param(
            SetupParameters(
                connection_tag=ConnectionTag.DOCKER_CONE_CLIENT_1,
                adapter_type=AdapterType.BoringTun,
                features=features_with_endpoint_providers([EndpointProvider.UPNP]),
            ),
        ),
        pytest.param(
            SetupParameters(
                connection_tag=ConnectionTag.DOCKER_CONE_CLIENT_1,
                adapter_type=AdapterType.LinuxNativeWg,
                features=features_with_endpoint_providers([EndpointProvider.UPNP]),
            ),
            marks=pytest.mark.linux_native,
        ),
        pytest.param(
            SetupParameters(
                connection_tag=ConnectionTag.WINDOWS_VM_1,
                adapter_type=AdapterType.WindowsNativeWg,
                features=features_with_endpoint_providers([EndpointProvider.UPNP]),
            ),
            marks=pytest.mark.windows,
        ),
        pytest.param(
            SetupParameters(
                connection_tag=ConnectionTag.WINDOWS_VM_1,
                adapter_type=AdapterType.WireguardGo,
                features=features_with_endpoint_providers([EndpointProvider.UPNP]),
            ),
            marks=pytest.mark.windows,
        ),
        pytest.param(
            SetupParameters(
                connection_tag=ConnectionTag.MAC_VM,
                adapter_type=AdapterType.BoringTun,
                features=features_with_endpoint_providers([EndpointProvider.UPNP]),
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
                adapter_type=AdapterType.BoringTun,
                features=features_with_endpoint_providers([EndpointProvider.UPNP]),
            )
        )
    ],
)
async def test_upnp_without_support(
    alpha_setup_params: SetupParameters, beta_setup_params: SetupParameters
) -> None:
    async with AsyncExitStack() as exit_stack:
        env = await exit_stack.enter_async_context(
            setup_environment(exit_stack, [alpha_setup_params, beta_setup_params])
        )
        (alpha_node, beta_node) = env.nodes
        (alpha_client, beta_client) = env.clients
        (alpha_conn_mgr, beta_conn_mgr) = env.connections

        await asyncio.gather(
            alpha_client.wait_for_state_on_any_derp([State.Connected]),
            beta_client.wait_for_state_on_any_derp([State.Connected]),
        )

        # Giving time for upnp gateway search to start
        with pytest.raises(asyncio.TimeoutError):
            await asyncio.gather(
                alpha_client.wait_for_event_peer(
                    beta_node.public_key,
                    [State.Connected],
                    [PathType.Direct],
                    timeout=10,
                ),
                beta_client.wait_for_event_peer(
                    alpha_node.public_key,
                    [State.Connected],
                    [PathType.Direct],
                    timeout=10,
                ),
            )

        await ping(beta_conn_mgr.connection, alpha_node.ip_addresses[0])
        await ping(alpha_conn_mgr.connection, beta_node.ip_addresses[0])
