import asyncio
import pytest
import telio
from contextlib import AsyncExitStack
from mesh_api import API
from telio import PathType
from telio_features import Direct, TelioFeatures
from utils import testing
from utils.connection_util import (
    ConnectionTag,
    ConnectionLimits,
    generate_connection_tracker_config,
    new_connection_with_conn_tracker,
)
from utils.ping import Ping

STUN_PROVIDER = ["stun"]

UHP_conn_client_types = [
    (
        STUN_PROVIDER,
        ConnectionTag.DOCKER_CONE_CLIENT_1,
        ConnectionTag.DOCKER_CONE_CLIENT_2,
        telio.AdapterType.BoringTun,
    ),
]


# NOTE: This test can only run on natlab linux containers or on linux
# machines caintaining old tcli v3.6 "/opt/bin/tcli-3.6".
@pytest.mark.asyncio
@pytest.mark.parametrize(
    "endpoint_providers, client1_type, client2_type, adapter_type",
    UHP_conn_client_types,
)
async def test_connect_different_telio_version_through_relay(
    endpoint_providers,
    client1_type,
    client2_type,
    adapter_type,
) -> None:
    async with AsyncExitStack() as exit_stack:
        api = API()

        (alpha, beta) = api.default_config_two_nodes()

        (
            alpha_conn,
            alpha_conn_tracker,
        ) = await exit_stack.enter_async_context(
            new_connection_with_conn_tracker(
                client1_type,
                generate_connection_tracker_config(
                    client1_type,
                    derp_1_limits=ConnectionLimits(1, 1),
                ),
            )
        )

        (
            beta_conn,
            beta_conn_tracker,
        ) = await exit_stack.enter_async_context(
            new_connection_with_conn_tracker(
                client2_type,
                generate_connection_tracker_config(
                    client2_type,
                    derp_1_limits=ConnectionLimits(1, 1),
                ),
            )
        )

        alpha_client = await exit_stack.enter_async_context(
            telio.Client(
                alpha_conn,
                alpha,
                adapter_type,
                telio_features=TelioFeatures(
                    direct=Direct(providers=endpoint_providers)
                ),
            ).run_meshnet(
                api.get_meshmap(alpha.id),
            )
        )

        beta_client_v3_6 = await exit_stack.enter_async_context(
            telio.Client(
                beta_conn,
                beta,
                adapter_type,
                telio_features=TelioFeatures(
                    direct=Direct(providers=endpoint_providers)
                ),
            ).run_meshnet(api.get_meshmap(beta.id), True)
        )

        await testing.wait_long(
            asyncio.gather(
                alpha_client.wait_for_state_on_any_derp([telio.State.Connected]),
                beta_client_v3_6.wait_for_state_on_any_derp([telio.State.Connected]),
            ),
        )

        await testing.wait_long(
            asyncio.gather(
                alpha_conn_tracker.wait_for_event("derp_1"),
                beta_conn_tracker.wait_for_event("derp_1"),
            )
        )

        # Hand only for alpha client because node event of telio 3.6
        # are not caught anymore
        await testing.wait_lengthy(
            asyncio.gather(
                alpha_client.wait_for_state_peer(
                    beta.public_key,
                    [telio.State.Connected],
                    [PathType.Relay],
                ),
            )
        )

        async with Ping(alpha_conn, beta.ip_addresses[0]).run() as ping:
            await testing.wait_long(ping.wait_for_next_ping())

        assert alpha_conn_tracker.get_out_of_limits() is None
        assert beta_conn_tracker.get_out_of_limits() is None
