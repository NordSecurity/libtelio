import asyncio
import pytest
import telio
from contextlib import AsyncExitStack
from helpers import SetupParameters, setup_mesh_nodes
from utils.connection_tracker import ConnectionLimits
from utils.connection_util import generate_connection_tracker_config, ConnectionTag


@pytest.mark.asyncio
@pytest.mark.timeout(180)
@pytest.mark.long
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
async def test_node_state_flickering(
    alpha_setup_params: SetupParameters, beta_setup_params: SetupParameters
) -> None:
    async with AsyncExitStack() as exit_stack:
        env = await setup_mesh_nodes(
            exit_stack, [alpha_setup_params, beta_setup_params]
        )
        alpha, beta = env.nodes
        client_alpha, client_beta = env.clients

        with pytest.raises(asyncio.TimeoutError):
            await asyncio.gather(
                client_alpha.wait_for_event_peer(
                    beta.public_key, list(telio.State), timeout=120
                ),
                client_beta.wait_for_event_peer(
                    alpha.public_key, list(telio.State), timeout=120
                ),
                client_alpha.wait_for_event_on_any_derp(list(telio.State), timeout=120),
                client_beta.wait_for_event_on_any_derp(list(telio.State), timeout=120),
            )
