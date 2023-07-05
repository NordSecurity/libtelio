from utils import Ping, stun
from contextlib import AsyncExitStack
from mesh_api import API
from telio import AdapterType
import config
import pytest
import telio
import utils.testing as testing
from utils import (
    ConnectionTag,
    new_connection_with_conn_tracker,
)
from utils.connection_tracker import (
    generate_connection_tracker_config,
    ConnectionLimits,
)
import asyncio


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "alpha_connection_tag,adapter_type",
    [
        pytest.param(
            ConnectionTag.DOCKER_CONE_CLIENT_1,
            telio.AdapterType.BoringTun,
        ),
        pytest.param(
            ConnectionTag.DOCKER_CONE_CLIENT_1,
            telio.AdapterType.LinuxNativeWg,
            marks=pytest.mark.linux_native,
        ),
        pytest.param(
            ConnectionTag.WINDOWS_VM,
            telio.AdapterType.WindowsNativeWg,
            marks=pytest.mark.windows,
        ),
        pytest.param(
            ConnectionTag.WINDOWS_VM,
            telio.AdapterType.WireguardGo,
            marks=pytest.mark.windows,
        ),
        pytest.param(
            ConnectionTag.MAC_VM,
            telio.AdapterType.Default,
            marks=pytest.mark.mac,
        ),
    ],
)
async def test_mesh_exit_through_peer(
    alpha_connection_tag: ConnectionTag,
    adapter_type: AdapterType,
) -> None:
    async with AsyncExitStack() as exit_stack:
        api = API()

        (alpha, beta) = api.default_config_two_nodes()
        (connection_alpha, alpha_conn_tracker) = await exit_stack.enter_async_context(
            new_connection_with_conn_tracker(
                alpha_connection_tag,
                generate_connection_tracker_config(
                    alpha_connection_tag,
                    derp_1_limits=ConnectionLimits(1, 1),
                ),
            )
        )
        (connection_beta, beta_conn_tracker) = await exit_stack.enter_async_context(
            new_connection_with_conn_tracker(
                ConnectionTag.DOCKER_CONE_CLIENT_2,
                generate_connection_tracker_config(
                    ConnectionTag.DOCKER_CONE_CLIENT_2,
                    derp_1_limits=ConnectionLimits(1, 1),
                    stun_limits=ConnectionLimits(1, 2),
                ),
            )
        )

        client_alpha = await exit_stack.enter_async_context(
            telio.Client(connection_alpha, alpha, adapter_type,).run_meshnet(
                api.get_meshmap(alpha.id),
            )
        )

        client_beta = await exit_stack.enter_async_context(
            telio.Client(connection_beta, beta,).run_meshnet(
                api.get_meshmap(beta.id),
            )
        )

        await testing.wait_long(
            asyncio.gather(
                client_alpha.wait_for_any_derp_state([telio.State.Connected]),
                client_beta.wait_for_any_derp_state([telio.State.Connected]),
            )
        )

        await testing.wait_long(
            asyncio.gather(
                alpha_conn_tracker.wait_for_event("derp_1"),
                beta_conn_tracker.wait_for_event("derp_1"),
            )
        )

        await testing.wait_long(
            asyncio.gather(
                client_alpha.handshake(beta.public_key),
                client_beta.handshake(alpha.public_key),
            )
        )

        async with Ping(connection_alpha, beta.ip_addresses[0]).run() as ping:
            await testing.wait_long(ping.wait_for_next_ping())

        await testing.wait_long(client_beta.get_router().create_exit_node_route())
        await testing.wait_long(
            client_alpha.connect_to_exit_node(
                beta.public_key,
            )
        )
        await testing.wait_long(client_alpha.handshake(beta.public_key))

        ip_alpha = await testing.wait_long(
            stun.get(connection_alpha, config.STUN_SERVER)
        )
        await testing.wait_long(beta_conn_tracker.wait_for_event("stun"))

        ip_beta = await testing.wait_long(stun.get(connection_beta, config.STUN_SERVER))
        await testing.wait_long(beta_conn_tracker.wait_for_event("stun"))

        assert ip_alpha == ip_beta
        assert alpha_conn_tracker.get_out_of_limits() is None
        assert beta_conn_tracker.get_out_of_limits() is None
