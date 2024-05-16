import asyncio
import pytest
from contextlib import AsyncExitStack
from helpers import SetupParameters, setup_mesh_nodes, setup_environment
from telio import AdapterType, PathType, State
from telio_features import Direct, TelioFeatures
from utils.asyncio_util import run_async_context
from utils.connection_util import ConnectionTag
from utils.ping import Ping
from utils.router import new_router, IPStack


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "alpha_setup_params",
    [
        SetupParameters(
            connection_tag=ConnectionTag.DOCKER_UPNP_CLIENT_1,
            adapter_type=AdapterType.BoringTun,
            features=TelioFeatures(direct=Direct(providers=["upnp"])),
        )
    ],
)
@pytest.mark.parametrize(
    "beta_setup_params",
    [
        SetupParameters(
            connection_tag=ConnectionTag.DOCKER_UPNP_CLIENT_2,
            adapter_type=AdapterType.BoringTun,
            features=TelioFeatures(direct=Direct(providers=["upnp"])),
        )
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
            async with Ping(alpha_conn.connection, beta.ip_addresses[0]).run() as ping:
                try:
                    await ping.wait_for_next_ping()
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

        async with Ping(beta_conn.connection, alpha.ip_addresses[0]).run() as ping:
            await ping.wait_for_next_ping(60)
        async with Ping(alpha_conn.connection, beta.ip_addresses[0]).run() as ping:
            await ping.wait_for_next_ping(60)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "alpha_setup_params",
    [
        pytest.param(
            SetupParameters(
                connection_tag=ConnectionTag.DOCKER_CONE_CLIENT_1,
                adapter_type=AdapterType.BoringTun,
                features=TelioFeatures(direct=Direct(providers=["upnp"])),
            ),
        ),
        pytest.param(
            SetupParameters(
                connection_tag=ConnectionTag.DOCKER_CONE_CLIENT_1,
                adapter_type=AdapterType.LinuxNativeWg,
                features=TelioFeatures(direct=Direct(providers=["upnp"])),
            ),
            marks=pytest.mark.linux_native,
        ),
        pytest.param(
            SetupParameters(
                connection_tag=ConnectionTag.WINDOWS_VM_1,
                adapter_type=AdapterType.WindowsNativeWg,
                features=TelioFeatures(direct=Direct(providers=["upnp"])),
            ),
            marks=pytest.mark.windows,
        ),
        pytest.param(
            SetupParameters(
                connection_tag=ConnectionTag.WINDOWS_VM_1,
                adapter_type=AdapterType.WireguardGo,
                features=TelioFeatures(direct=Direct(providers=["upnp"])),
            ),
            marks=pytest.mark.windows,
        ),
        pytest.param(
            SetupParameters(
                connection_tag=ConnectionTag.MAC_VM,
                adapter_type=AdapterType.BoringTun,
                features=TelioFeatures(direct=Direct(providers=["upnp"])),
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
                features=TelioFeatures(direct=Direct(providers=["upnp"])),
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

        async with Ping(
            beta_conn_mgr.connection, alpha_node.ip_addresses[0]
        ).run() as ping:
            await ping.wait_for_next_ping()
        async with Ping(
            alpha_conn_mgr.connection, beta_node.ip_addresses[0]
        ).run() as ping:
            await ping.wait_for_next_ping()
