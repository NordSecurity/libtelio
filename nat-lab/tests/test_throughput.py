import pytest
from contextlib import AsyncExitStack
from helpers import setup_mesh_nodes, SetupParameters
from utils.bindings import TelioAdapterType
from utils.connection_util import ConnectionTag

DEFAULT_WAITING_TIME = 2


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "alpha_setup_params",
    [
        pytest.param(
            SetupParameters(
                connection_tag=ConnectionTag.DOCKER_CONE_CLIENT_1,
                adapter_type_override=TelioAdapterType.LINUX_NATIVE_TUN,
            ),
        ),
    ],
)
@pytest.mark.parametrize(
    "beta_setup_params",
    [
        pytest.param(
            SetupParameters(
                connection_tag=ConnectionTag.DOCKER_CONE_CLIENT_2,
                adapter_type_override=TelioAdapterType.LINUX_NATIVE_TUN,
            ),
        ),
    ],
)
async def test_throughput(
    alpha_setup_params: SetupParameters,
    beta_setup_params: SetupParameters,
) -> None:
    async with AsyncExitStack() as exit_stack:
        env = await setup_mesh_nodes(
            exit_stack, [alpha_setup_params, beta_setup_params]
        )
        [client_alpha] = env.clients

        await client_alpha.enable_magic_dns
        await client_alpha.restart_interface()

        await client_alpha.wait_for_log("Updating local addr cache")
