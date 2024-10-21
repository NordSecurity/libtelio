import asyncio
import pytest
import re
from contextlib import AsyncExitStack
from helpers import SetupParameters, setup_mesh_nodes, setup_environment
from utils.asyncio_util import run_async_context
from utils.bindings import (
    features_with_endpoint_providers,
    EndpointProvider,
    PathType,
    NodeState,
    TelioAdapterType,
    RelayState,
)
from utils.connection_util import ConnectionTag
from utils.ping import ping
from utils.router import new_router, IPStack


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "alpha_setup_params",
    [
        SetupParameters(
            connection_tag=ConnectionTag.DOCKER_UPNP_CLIENT_1,
            adapter_type_override=TelioAdapterType.BORING_TUN,
            features=features_with_endpoint_providers([EndpointProvider.UPNP]),
        ),
    ],
)
@pytest.mark.parametrize(
    "beta_setup_params",
    [
        SetupParameters(
            connection_tag=ConnectionTag.DOCKER_UPNP_CLIENT_2,
            adapter_type_override=TelioAdapterType.BORING_TUN,
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
                    alpha_client.wait_for_event_peer(
                        beta.public_key, [NodeState.CONNECTED]
                    )
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
                beta.public_key, [NodeState.CONNECTED], [PathType.DIRECT]
            ),
            beta_client.wait_for_event_peer(
                alpha.public_key, [NodeState.CONNECTED], [PathType.DIRECT]
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
                adapter_type_override=TelioAdapterType.BORING_TUN,
                features=features_with_endpoint_providers([EndpointProvider.UPNP]),
            ),
        ),
        pytest.param(
            SetupParameters(
                connection_tag=ConnectionTag.DOCKER_CONE_CLIENT_1,
                adapter_type_override=TelioAdapterType.LINUX_NATIVE_TUN,
                features=features_with_endpoint_providers([EndpointProvider.UPNP]),
            ),
            marks=pytest.mark.linux_native,
        ),
        pytest.param(
            SetupParameters(
                connection_tag=ConnectionTag.WINDOWS_VM_1,
                adapter_type_override=TelioAdapterType.WINDOWS_NATIVE_TUN,
                features=features_with_endpoint_providers([EndpointProvider.UPNP]),
            ),
            marks=pytest.mark.windows,
        ),
        pytest.param(
            SetupParameters(
                connection_tag=ConnectionTag.WINDOWS_VM_1,
                adapter_type_override=TelioAdapterType.WIREGUARD_GO_TUN,
                features=features_with_endpoint_providers([EndpointProvider.UPNP]),
            ),
            marks=pytest.mark.windows,
        ),
        pytest.param(
            SetupParameters(
                connection_tag=ConnectionTag.MAC_VM,
                adapter_type_override=TelioAdapterType.BORING_TUN,
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
                adapter_type_override=TelioAdapterType.BORING_TUN,
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
            alpha_client.wait_for_state_on_any_derp([RelayState.CONNECTED]),
            beta_client.wait_for_state_on_any_derp([RelayState.CONNECTED]),
        )

        # Giving time for upnp gateway search to start
        with pytest.raises(asyncio.TimeoutError):
            await asyncio.gather(
                alpha_client.wait_for_event_peer(
                    beta_node.public_key,
                    [NodeState.CONNECTED],
                    [PathType.DIRECT],
                    timeout=10,
                ),
                beta_client.wait_for_event_peer(
                    alpha_node.public_key,
                    [NodeState.CONNECTED],
                    [PathType.DIRECT],
                    timeout=10,
                ),
            )

        await ping(beta_conn_mgr.connection, alpha_node.ip_addresses[0])
        await ping(alpha_conn_mgr.connection, beta_node.ip_addresses[0])


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "alpha_setup_params",
    [
        SetupParameters(
            connection_tag=ConnectionTag.DOCKER_UPNP_CLIENT_1,
            adapter_type_override=TelioAdapterType.BORING_TUN,
            features=features_with_endpoint_providers([EndpointProvider.UPNP]),
        ),
    ],
)
@pytest.mark.parametrize(
    "beta_setup_params",
    [
        SetupParameters(
            connection_tag=ConnectionTag.DOCKER_SYMMETRIC_CLIENT_1,
            adapter_type_override=TelioAdapterType.BORING_TUN,
            features=features_with_endpoint_providers([EndpointProvider.LOCAL]),
        ),
    ],
)
async def test_upnp_port_lease_duration(
    alpha_setup_params: SetupParameters, beta_setup_params: SetupParameters
) -> None:
    async with AsyncExitStack() as exit_stack:
        # once the endpoint interval expires, the endpoint is validated and if
        # the lease duration left is less than 25% the port mappings are renewed.
        lease_duration_s = 40

        assert alpha_setup_params.features.direct
        assert alpha_setup_params.features.direct.upnp_features
        alpha_setup_params.features.direct.upnp_features.lease_duration_s = (
            lease_duration_s
        )

        assert alpha_setup_params.features.direct.endpoint_interval_secs
        alpha_setup_params.features.direct.endpoint_interval_secs = 5
        assert alpha_setup_params.features.direct.endpoint_providers_optimization
        alpha_setup_params.features.direct.endpoint_providers_optimization.optimize_direct_upgrade_upnp = (
            False
        )

        env = await exit_stack.enter_async_context(
            setup_environment(exit_stack, [alpha_setup_params, beta_setup_params])
        )
        (alpha_node, beta_node) = env.nodes
        (alpha_client, beta_client) = env.clients
        (alpha_conn_mgr, _) = env.connections
        alpha_conn = alpha_conn_mgr.connection

        assert alpha_conn_mgr.gw_connection
        alpha_gw_router = new_router(alpha_conn_mgr.gw_connection, IPStack.IPv4v6)

        # Clean upnp mappings
        async with AsyncExitStack() as temp_exit_stack:
            await temp_exit_stack.enter_async_context(alpha_gw_router.reset_upnpd())

        # this check should be done before endpoint interval triggers a new mapping (optimal > 5s)
        upnpc_cmd = await alpha_conn.create_process(["upnpc", "-i", "-l"]).execute()
        assert re.search("^ [0-9]+ UDP", upnpc_cmd.get_stdout(), re.MULTILINE) is None

        await asyncio.gather(
            alpha_client.wait_for_state_on_any_derp([RelayState.CONNECTED]),
            beta_client.wait_for_state_on_any_derp([RelayState.CONNECTED]),
            alpha_client.wait_for_event_peer(
                beta_node.public_key, [NodeState.CONNECTED], [PathType.DIRECT]
            ),
            beta_client.wait_for_event_peer(
                alpha_node.public_key, [NodeState.CONNECTED], [PathType.DIRECT]
            ),
        )

        upnpc_cmd = await alpha_conn.create_process(["upnpc", "-i", "-l"]).execute()
        mappings_search = re.findall(
            "^ [0-9]+ UDP", upnpc_cmd.get_stdout(), re.MULTILINE
        )
        assert len(mappings_search) == 2

        await asyncio.sleep(lease_duration_s)

        # telio-traversal shouldn't let port mappings expire
        upnpc_cmd = await alpha_conn.create_process(["upnpc", "-i", "-l"]).execute()
        mappings_search = re.findall(
            "^ [0-9]+ UDP", upnpc_cmd.get_stdout(), re.MULTILINE
        )
        assert len(mappings_search) == 2

        await alpha_client.stop_device()
        await asyncio.sleep(lease_duration_s)

        # upnpn mappings should have expired
        upnpc_cmd = await alpha_conn.create_process(["upnpc", "-i", "-l"]).execute()
        assert re.search("^ [0-9]+ UDP", upnpc_cmd.get_stdout(), re.MULTILINE) is None
