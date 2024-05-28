import asyncio
import pytest
import telio
from contextlib import AsyncExitStack
from helpers import setup_mesh_nodes, SetupParameters
from utils.connection_tracker import ConnectionLimits
from utils.connection_util import generate_connection_tracker_config, ConnectionTag
from utils.ping import Ping


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "alpha_setup_params",
    [
        pytest.param(
            SetupParameters(
                connection_tag=ConnectionTag.DOCKER_CONE_CLIENT_1,
                adapter_type=telio.AdapterType.BoringTun,
                connection_tracker_config=generate_connection_tracker_config(
                    ConnectionTag.DOCKER_CONE_CLIENT_1,
                    derp_1_limits=ConnectionLimits(2, 2),
                ),
            )
        ),
        pytest.param(
            SetupParameters(
                connection_tag=ConnectionTag.DOCKER_CONE_CLIENT_1,
                adapter_type=telio.AdapterType.LinuxNativeWg,
                connection_tracker_config=generate_connection_tracker_config(
                    ConnectionTag.DOCKER_CONE_CLIENT_1,
                    derp_1_limits=ConnectionLimits(2, 2),
                ),
            ),
            marks=pytest.mark.linux_native,
        ),
        pytest.param(
            SetupParameters(
                connection_tag=ConnectionTag.WINDOWS_VM_1,
                adapter_type=telio.AdapterType.WindowsNativeWg,
                connection_tracker_config=generate_connection_tracker_config(
                    ConnectionTag.WINDOWS_VM_1,
                    derp_1_limits=ConnectionLimits(2, 2),
                ),
            ),
            marks=[
                pytest.mark.windows,
            ],
        ),
        pytest.param(
            SetupParameters(
                connection_tag=ConnectionTag.WINDOWS_VM_1,
                adapter_type=telio.AdapterType.WireguardGo,
                connection_tracker_config=generate_connection_tracker_config(
                    ConnectionTag.WINDOWS_VM_1,
                    derp_1_limits=ConnectionLimits(2, 2),
                ),
            ),
            marks=[
                pytest.mark.windows,
            ],
        ),
        pytest.param(
            SetupParameters(
                connection_tag=ConnectionTag.MAC_VM,
                adapter_type=telio.AdapterType.BoringTun,
                connection_tracker_config=generate_connection_tracker_config(
                    ConnectionTag.MAC_VM,
                    derp_1_limits=ConnectionLimits(2, 2),
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
                    derp_1_limits=ConnectionLimits(1, 1),
                ),
            )
        )
    ],
)
async def test_mesh_reconnect(
    alpha_setup_params: SetupParameters, beta_setup_params: SetupParameters
) -> None:
    async with AsyncExitStack() as exit_stack:
        env = await setup_mesh_nodes(
            exit_stack, [alpha_setup_params, beta_setup_params]
        )
        api = env.api
        alpha, beta = env.nodes
        alpha_connection, beta_connection = [
            conn.connection for conn in env.connections
        ]
        client_alpha, client_beta = env.clients

        async with Ping(alpha_connection, beta.ip_addresses[0]).run() as ping:
            await ping.wait_for_next_ping()
        async with Ping(beta_connection, alpha.ip_addresses[0]).run() as ping:
            await ping.wait_for_next_ping()

        await client_alpha.stop_device()

        with pytest.raises(asyncio.TimeoutError):
            async with Ping(beta_connection, alpha.ip_addresses[0]).run() as ping:
                await ping.wait_for_next_ping(15)

        await client_alpha.simple_start()
        await client_alpha.set_meshmap(api.get_meshmap(alpha.id))

        await asyncio.gather(
            client_alpha.wait_for_event_peer(beta.public_key, [telio.State.Connected]),
            client_alpha.wait_for_event_on_any_derp([telio.State.Connected]),
        )

        await asyncio.gather(
            client_alpha.wait_for_state_peer(beta.public_key, [telio.State.Connected]),
            client_beta.wait_for_state_peer(alpha.public_key, [telio.State.Connected]),
        )

        async with Ping(alpha_connection, beta.ip_addresses[0]).run() as ping:
            await ping.wait_for_next_ping()

        async with Ping(beta_connection, alpha.ip_addresses[0]).run() as ping:
            await ping.wait_for_next_ping()
