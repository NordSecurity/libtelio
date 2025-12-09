import pytest
from contextlib import AsyncExitStack
from tests.helpers import setup_mesh_nodes, SetupParameters, ping_between_all_nodes
from tests.utils.bindings import default_features, TelioAdapterType
from tests.utils.connection import ConnectionTag
from tests.utils.testing import log_test_passed

BUFFER_SIZE = 1310720


@pytest.mark.asyncio
async def test_custom_socket_buffers_on_neptun() -> None:
    async with AsyncExitStack() as exit_stack:
        env = await setup_mesh_nodes(
            exit_stack,
            [
                SetupParameters(
                    connection_tag=ConnectionTag.DOCKER_CONE_CLIENT_1,
                    adapter_type_override=TelioAdapterType.NEP_TUN,
                    features=default_features(custom_skt_buffer_size=BUFFER_SIZE),
                ),
                SetupParameters(
                    connection_tag=ConnectionTag.DOCKER_CONE_CLIENT_2,
                ),
            ],
        )

        [client_alpha, _] = env.clients
        await client_alpha.wait_for_log(
            'Socket buffer "RcvBuf" set with value ' + str(BUFFER_SIZE)
        )
        # Ping to check connection works both ways
        await ping_between_all_nodes(env)
        log_test_passed()
