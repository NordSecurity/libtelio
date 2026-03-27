import pytest
from tests.helpers import SetupParameters, Environment, ping_between_all_nodes
from tests.utils.bindings import default_features, TelioAdapterType
from tests.utils.connection import ConnectionTag

pytest_plugins = ["tests.helpers_fixtures"]

BUFFER_SIZE = 1310720


@pytest.mark.parametrize(
    "alpha_setup_params, beta_setup_params",
    [
        pytest.param(
            SetupParameters(
                connection_tag=ConnectionTag.DOCKER_CONE_CLIENT_1,
                adapter_type_override=TelioAdapterType.NEP_TUN,
                features=default_features(custom_skt_buffer_size=BUFFER_SIZE),
            ),
            SetupParameters(
                connection_tag=ConnectionTag.DOCKER_CONE_CLIENT_2,
            ),
        ),
    ],
)
@pytest.mark.asyncio
async def test_custom_socket_buffers_on_neptun(
    alpha_setup_params: SetupParameters,  # pylint: disable=unused-argument
    beta_setup_params: SetupParameters,  # pylint: disable=unused-argument
    env_mesh: Environment,
) -> None:
    client_alpha = env_mesh.clients[0]
    await client_alpha.wait_for_log(
        'Socket buffer "RcvBuf" set with value ' + str(BUFFER_SIZE)
    )
    # Ping to check connection works both ways
    await ping_between_all_nodes(env_mesh)
