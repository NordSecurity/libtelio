import asyncio
import pytest
from contextlib import AsyncExitStack
from helpers import SetupParameters, setup_mesh_nodes
from telio import AdapterType, PathType, State
from telio_features import Direct, TelioFeatures
from utils import testing
from utils.connection_util import ConnectionTag
from utils.ping import Ping
from utils.router import new_router


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

        alpha_gw_router = new_router(alpha_conn.gw_connection)
        beta_gw_router = new_router(beta_conn.gw_connection)

        # Shutoff Upnpd on both gateways to wipe out all upnp created external
        # routes, this also requires to wipe-out the contrack list
        async with alpha_gw_router.reset_upnpd(), beta_gw_router.reset_upnpd():
            with pytest.raises(asyncio.TimeoutError):
                async with Ping(
                    alpha_conn.connection, beta.ip_addresses[0]
                ).run() as ping:
                    await testing.wait_long(ping.wait_for_next_ping())

        await testing.wait_defined(
            asyncio.gather(
                alpha_client.wait_for_event_peer(
                    beta.public_key, [State.Connected], [PathType.Direct]
                ),
                beta_client.wait_for_event_peer(
                    alpha.public_key, [State.Connected], [PathType.Direct]
                ),
            ),
            60,
        )

        async with Ping(beta_conn.connection, alpha.ip_addresses[0]).run() as ping:
            await testing.wait_lengthy(ping.wait_for_next_ping())
        async with Ping(alpha_conn.connection, beta.ip_addresses[0]).run() as ping:
            await testing.wait_lengthy(ping.wait_for_next_ping())
