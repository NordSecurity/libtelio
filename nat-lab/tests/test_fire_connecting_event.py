import asyncio
import pytest
from contextlib import AsyncExitStack
from tests import timeouts
from tests.helpers import SetupParameters, setup_mesh_nodes
from tests.utils.bindings import NodeState, TelioAdapterType
from tests.utils.connection import ConnectionTag
from tests.utils.connection_util import generate_connection_tracker_config
from tests.utils.ping import ping


@pytest.mark.asyncio
@pytest.mark.long
@pytest.mark.timeout(timeouts.TEST_FIRE_CONNECTING_EVENT_TIMEOUT)
@pytest.mark.parametrize(
    "alpha_setup_params",
    [
        SetupParameters(
            connection_tag=ConnectionTag.DOCKER_CONE_CLIENT_1,
            adapter_type_override=TelioAdapterType.NEP_TUN,
            connection_tracker_config=generate_connection_tracker_config(
                ConnectionTag.DOCKER_CONE_CLIENT_1, derp_1_limits=(1, 1)
            ),
        )
    ],
)
@pytest.mark.parametrize(
    "beta_setup_params",
    [
        SetupParameters(
            connection_tag=ConnectionTag.DOCKER_CONE_CLIENT_2,
            connection_tracker_config=generate_connection_tracker_config(
                ConnectionTag.DOCKER_CONE_CLIENT_2, derp_1_limits=(1, 1)
            ),
        )
    ],
)
async def test_fire_connecting_event(
    alpha_setup_params: SetupParameters, beta_setup_params: SetupParameters
) -> None:
    async with AsyncExitStack() as exit_stack:
        env = await setup_mesh_nodes(
            exit_stack, [alpha_setup_params, beta_setup_params]
        )
        _, beta = env.nodes
        connection_alpha, _ = [conn.connection for conn in env.connections]
        client_alpha, client_beta = env.clients

        await ping(connection_alpha, beta.ip_addresses[0])

        await client_beta.stop_device()

        with pytest.raises(asyncio.TimeoutError):
            await ping(connection_alpha, beta.ip_addresses[0], 15)

        await client_alpha.wait_for_event_peer(beta.public_key, [NodeState.CONNECTING])
