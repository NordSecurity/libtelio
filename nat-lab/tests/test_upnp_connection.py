import asyncio
import pytest
import re
from contextlib import AsyncExitStack
from tests.helpers import SetupParameters, setup_mesh_nodes, setup_environment
from tests.utils.asyncio_util import run_async_context, run_async_contexts
from tests.utils.bindings import (
    features_with_endpoint_providers,
    EndpointProvider,
    PathType,
    NodeState,
    TelioAdapterType,
    RelayState,
)
from tests.utils.connection import ConnectionTag
from tests.utils.logger import log
from tests.utils.ping import ping
from tests.utils.process import ProcessExecError
from tests.utils.router import new_router, IPStack
from tests.utils.testing import log_test_passed


async def execute_upnpc_with_retry(connection, timeout=10.0):
    start_time = asyncio.get_event_loop().time()
    while True:
        try:
            return await connection.create_process(["upnpc", "-i", "-l"]).execute()
        except ProcessExecError as e:
            if asyncio.get_event_loop().time() - start_time >= timeout:
                log.error("Timeout while waiting for upnpc to start: %s", e)
                raise

        await asyncio.sleep(1.0)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "alpha_setup_params",
    [
        SetupParameters(
            connection_tag=ConnectionTag.DOCKER_UPNP_CLIENT_1,
            adapter_type_override=TelioAdapterType.NEP_TUN,
            features=features_with_endpoint_providers([EndpointProvider.UPNP]),
        ),
    ],
)
@pytest.mark.parametrize(
    "beta_setup_params",
    [
        SetupParameters(
            connection_tag=ConnectionTag.DOCKER_UPNP_CLIENT_2,
            adapter_type_override=TelioAdapterType.NEP_TUN,
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
            task = await temp_exit_stack.enter_async_context(
                run_async_context(
                    alpha_client.wait_for_event_peer(
                        beta.public_key, [NodeState.CONNECTED]
                    )
                )
            )

            await asyncio.gather(*[
                temp_exit_stack.enter_async_context(alpha_gw_router.reset_upnpd()),
                temp_exit_stack.enter_async_context(beta_gw_router.reset_upnpd()),
            ])

            try:
                await ping(alpha_conn.connection, beta.ip_addresses[0], 15)
            except asyncio.TimeoutError:
                pass
            else:
                # if no timeout exception happens, this means, that peers connected through relay
                # faster than we expected, but if no relay event occurs, this means, that something
                # else was wrong, so we assert

                await asyncio.wait_for(task, 1)

            direct_events = await exit_stack.enter_async_context(
                run_async_contexts([
                    alpha_client.wait_for_event_peer(
                        beta.public_key, [NodeState.CONNECTED], [PathType.DIRECT]
                    ),
                    beta_client.wait_for_event_peer(
                        alpha.public_key, [NodeState.CONNECTED], [PathType.DIRECT]
                    ),
                ])
            )

        await asyncio.gather(*direct_events)

        await asyncio.gather(*[
            ping(beta_conn.connection, alpha.ip_addresses[0]),
            ping(alpha_conn.connection, beta.ip_addresses[0]),
        ])

        # LLT-5532: To be cleaned up...
        alpha_client.allow_errors(
            ["telio_proxy::proxy.*Unable to send. WG Address not available"]
        )
        beta_client.allow_errors(
            ["telio_proxy::proxy.*Unable to send. WG Address not available"]
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
                connection_tag=ConnectionTag.VM_WINDOWS_1,
                adapter_type_override=TelioAdapterType.WINDOWS_NATIVE_TUN,
                features=features_with_endpoint_providers([EndpointProvider.UPNP]),
            ),
            marks=pytest.mark.windows,
        ),
        pytest.param(
            SetupParameters(
                connection_tag=ConnectionTag.VM_MAC,
                adapter_type_override=TelioAdapterType.NEP_TUN,
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
                adapter_type_override=TelioAdapterType.NEP_TUN,
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
        log_test_passed()


@pytest.mark.asyncio
@pytest.mark.parametrize("battery_optimization", [True, False])
@pytest.mark.parametrize(
    "alpha_setup_params",
    [
        SetupParameters(
            connection_tag=ConnectionTag.DOCKER_UPNP_CLIENT_1,
            adapter_type_override=TelioAdapterType.NEP_TUN,
            features=features_with_endpoint_providers([EndpointProvider.UPNP]),
        ),
    ],
)
@pytest.mark.parametrize(
    "beta_setup_params",
    [
        SetupParameters(
            connection_tag=ConnectionTag.DOCKER_SYMMETRIC_CLIENT_1,
            adapter_type_override=TelioAdapterType.NEP_TUN,
            features=features_with_endpoint_providers([EndpointProvider.LOCAL]),
        ),
    ],
)
async def test_upnp_port_lease_duration(
    battery_optimization: bool,
    alpha_setup_params: SetupParameters,
    beta_setup_params: SetupParameters,
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
            battery_optimization
        )

        env = await setup_mesh_nodes(
            exit_stack, [alpha_setup_params, beta_setup_params]
        )
        (alpha_client, _) = env.clients
        (alpha_conn_mgr, _) = env.connections
        alpha_conn = alpha_conn_mgr.connection

        upnpc_cmd = await execute_upnpc_with_retry(alpha_conn)
        mappings_search = re.findall(
            "^ [0-9]+ UDP", upnpc_cmd.get_stdout(), re.MULTILINE
        )
        assert len(mappings_search) == 2

        await asyncio.sleep(lease_duration_s)

        # telio-traversal shouldn't let port mappings expire
        upnpc_cmd = await execute_upnpc_with_retry(alpha_conn)
        mappings_search = re.findall(
            "^ [0-9]+ UDP", upnpc_cmd.get_stdout(), re.MULTILINE
        )
        assert len(mappings_search) == 2

        await alpha_client.stop_device()
        await asyncio.sleep(lease_duration_s)

        # upnpn mappings should have expired
        upnpc_cmd = await execute_upnpc_with_retry(alpha_conn)
        assert re.search("^ [0-9]+ UDP", upnpc_cmd.get_stdout(), re.MULTILINE) is None
        log_test_passed()
