import asyncio
import pytest
import telio
from contextlib import AsyncExitStack
from helpers import SetupParameters, setup_mesh_nodes
from mesh_api import API
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
                    derp_1_limits=ConnectionLimits(1, 1),
                ),
            )
        ),
        pytest.param(
            SetupParameters(
                connection_tag=ConnectionTag.DOCKER_CONE_CLIENT_1,
                adapter_type=telio.AdapterType.LinuxNativeWg,
                connection_tracker_config=generate_connection_tracker_config(
                    ConnectionTag.DOCKER_CONE_CLIENT_1,
                    derp_1_limits=ConnectionLimits(1, 1),
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
                    derp_1_limits=ConnectionLimits(1, 1),
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
                    derp_1_limits=ConnectionLimits(1, 1),
                ),
            ),
            marks=pytest.mark.windows,
        ),
        pytest.param(
            SetupParameters(
                connection_tag=ConnectionTag.MAC_VM,
                adapter_type=telio.AdapterType.BoringTun,
                connection_tracker_config=generate_connection_tracker_config(
                    ConnectionTag.MAC_VM,
                    derp_1_limits=ConnectionLimits(1, 1),
                ),
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
                connection_tracker_config=generate_connection_tracker_config(
                    ConnectionTag.DOCKER_CONE_CLIENT_2,
                    derp_1_limits=ConnectionLimits(1, 1),
                ),
            )
        )
    ],
)
@pytest.mark.parametrize(
    "gamma_setup_params",
    [
        pytest.param(
            SetupParameters(
                connection_tag=ConnectionTag.DOCKER_SYMMETRIC_CLIENT_1,
                connection_tracker_config=generate_connection_tracker_config(
                    ConnectionTag.DOCKER_SYMMETRIC_CLIENT_1,
                    derp_1_limits=ConnectionLimits(1, 1),
                ),
            )
        )
    ],
)
async def test_mesh_remove_node(
    alpha_setup_params: SetupParameters,
    beta_setup_params: SetupParameters,
    gamma_setup_params: SetupParameters,
) -> None:
    async with AsyncExitStack() as exit_stack:
        api = API()

        (alpha, beta, gamma) = api.default_config_three_nodes()

        alpha.set_peer_firewall_settings(beta.id, allow_incoming_connections=False)
        beta.set_peer_firewall_settings(gamma.id, allow_incoming_connections=False)
        gamma.set_peer_firewall_settings(alpha.id, allow_incoming_connections=False)

        env = await setup_mesh_nodes(
            exit_stack,
            [alpha_setup_params, beta_setup_params, gamma_setup_params],
            provided_api=api,
        )

        connection_alpha, connection_beta, connection_gamma = [
            conn.connection for conn in env.connections
        ]
        client_alpha, client_beta, _ = env.clients

        async with Ping(connection_alpha, beta.ip_addresses[0]).run() as ping:
            await ping.wait_for_next_ping()
        async with Ping(connection_beta, gamma.ip_addresses[0]).run() as ping:
            await ping.wait_for_next_ping()
        async with Ping(connection_gamma, alpha.ip_addresses[0]).run() as ping:
            await ping.wait_for_next_ping()

        api.remove(gamma.id)

        await client_alpha.set_meshmap(api.get_meshmap(alpha.id))
        await client_beta.set_meshmap(api.get_meshmap(beta.id))

        async with Ping(connection_alpha, beta.ip_addresses[0]).run() as ping:
            await ping.wait_for_next_ping()
        with pytest.raises(asyncio.TimeoutError):
            async with Ping(connection_beta, gamma.ip_addresses[0]).run() as ping:
                await ping.wait_for_next_ping(5)
        with pytest.raises(asyncio.TimeoutError):
            async with Ping(connection_gamma, alpha.ip_addresses[0]).run() as ping:
                await ping.wait_for_next_ping(5)
