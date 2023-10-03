import asyncio
import pytest
import telio
from contextlib import AsyncExitStack
from mesh_api import API
from utils import testing
from utils.connection_tracker import ConnectionLimits
from utils.connection_util import (
    generate_connection_tracker_config,
    ConnectionTag,
    new_connection_with_conn_tracker,
)
from utils.ping import Ping


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "alpha_connection_tag, adapter_type",
    [
        pytest.param(ConnectionTag.DOCKER_CONE_CLIENT_1, telio.AdapterType.BoringTun),
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
            ConnectionTag.MAC_VM, telio.AdapterType.Default, marks=pytest.mark.mac
        ),
    ],
)
async def test_connected_state_after_routing(
    alpha_connection_tag: ConnectionTag, adapter_type: telio.AdapterType
) -> None:
    async with AsyncExitStack() as exit_stack:
        api = API()

        (alpha, beta) = api.default_config_two_nodes()

        (connection_alpha, alpha_conn_tracker) = await exit_stack.enter_async_context(
            new_connection_with_conn_tracker(
                alpha_connection_tag,
                generate_connection_tracker_config(
                    alpha_connection_tag, derp_1_limits=ConnectionLimits(1, 1)
                ),
            )
        )
        (connection_beta, beta_conn_tracker) = await exit_stack.enter_async_context(
            new_connection_with_conn_tracker(
                ConnectionTag.DOCKER_CONE_CLIENT_2,
                generate_connection_tracker_config(
                    ConnectionTag.DOCKER_CONE_CLIENT_2,
                    derp_1_limits=ConnectionLimits(1, 1),
                ),
            )
        )

        client_alpha = await exit_stack.enter_async_context(
            telio.Client(connection_alpha, alpha, adapter_type).run_meshnet(
                api.get_meshmap(alpha.id)
            )
        )

        client_beta = await exit_stack.enter_async_context(
            telio.Client(connection_beta, beta).run_meshnet(api.get_meshmap(beta.id))
        )

        await testing.wait_lengthy(
            asyncio.gather(
                client_alpha.wait_for_state_on_any_derp([telio.State.Connected]),
                client_beta.wait_for_state_on_any_derp([telio.State.Connected]),
                alpha_conn_tracker.wait_for_event("derp_1"),
                beta_conn_tracker.wait_for_event("derp_1"),
            )
        )
        await testing.wait_lengthy(
            asyncio.gather(
                client_alpha.wait_for_state_peer(
                    beta.public_key, [telio.State.Connected]
                ),
                client_beta.wait_for_state_peer(
                    alpha.public_key, [telio.State.Connected]
                ),
            )
        )

        await testing.wait_long(client_beta.get_router().create_exit_node_route())
        await testing.wait_long(client_alpha.connect_to_exit_node(beta.public_key))

        await testing.wait_long(
            client_alpha.wait_for_event_peer(beta.public_key, [telio.State.Connected])
        )

        await testing.wait_long(client_alpha.disconnect_from_exit_nodes())

        await testing.wait_long(
            client_alpha.wait_for_event_peer(beta.public_key, [telio.State.Connected])
        )

        async with Ping(connection_alpha, beta.ip_addresses[0]).run() as ping:
            await testing.wait_long(ping.wait_for_next_ping())

        assert alpha_conn_tracker.get_out_of_limits() is None
        assert beta_conn_tracker.get_out_of_limits() is None
