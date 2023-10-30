import pytest
import telio
from contextlib import AsyncExitStack
from helpers import SetupParameters, setup_mesh_nodes
from utils import testing
from utils.asyncio_util import run_async_context
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
                connection_tag=ConnectionTag.WINDOWS_VM,
                adapter_type=telio.AdapterType.WindowsNativeWg,
                connection_tracker_config=generate_connection_tracker_config(
                    ConnectionTag.WINDOWS_VM,
                    derp_1_limits=ConnectionLimits(1, 1),
                ),
            ),
            marks=pytest.mark.windows,
        ),
        pytest.param(
            SetupParameters(
                connection_tag=ConnectionTag.WINDOWS_VM,
                adapter_type=telio.AdapterType.WireguardGo,
                connection_tracker_config=generate_connection_tracker_config(
                    ConnectionTag.WINDOWS_VM,
                    derp_1_limits=ConnectionLimits(1, 1),
                ),
            ),
            marks=[
                pytest.mark.windows,
                pytest.mark.xfail(reason="Test is flaky - LLT-4357"),
            ],
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
async def test_connected_state_after_routing(
    alpha_setup_params: SetupParameters, beta_setup_params: SetupParameters
) -> None:
    async with AsyncExitStack() as exit_stack:
        env = await setup_mesh_nodes(
            exit_stack, [alpha_setup_params, beta_setup_params]
        )

        _, beta = env.nodes
        client_alpha, client_beta = env.clients
        conn_alpha, _ = env.connections

        await testing.wait_long(client_beta.get_router().create_exit_node_route())

        async with run_async_context(
            client_alpha.wait_for_event_peer(beta.public_key, [telio.State.Connected])
        ) as task:
            await testing.wait_long(client_alpha.connect_to_exit_node(beta.public_key))
            await testing.wait_long(task)

        async with run_async_context(
            client_alpha.wait_for_event_peer(beta.public_key, [telio.State.Connected])
        ) as task:
            await testing.wait_long(client_alpha.disconnect_from_exit_nodes())
            await testing.wait_long(task)

        async with Ping(conn_alpha.connection, beta.ip_addresses[0]).run() as ping:
            await testing.wait_long(ping.wait_for_next_ping())
