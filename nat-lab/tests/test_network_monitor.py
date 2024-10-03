import asyncio
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
                connection_tag=ConnectionTag.DOCKER_SHARED_CLIENT_1,
                adapter_type_override=TelioAdapterType.BORING_TUN,
            ),
        ),
        pytest.param(
            SetupParameters(
                connection_tag=ConnectionTag.WINDOWS_VM_1,
                adapter_type_override=TelioAdapterType.WIREGUARD_GO_TUN,
            ),
            marks=[pytest.mark.windows],
        ),
        pytest.param(
            SetupParameters(
                connection_tag=ConnectionTag.MAC_VM,
                adapter_type_override=TelioAdapterType.BORING_TUN,
            ),
            marks=[
                pytest.mark.mac,
            ],
        ),
    ],
)
async def test_network_monitor(
    alpha_setup_params: SetupParameters,
) -> None:
    async with AsyncExitStack() as exit_stack:
        env = await setup_mesh_nodes(exit_stack, [alpha_setup_params])
        [client_alpha] = env.clients

        await asyncio.sleep(DEFAULT_WAITING_TIME)
        await client_alpha.restart_interface()

        await client_alpha.wait_for_log("Updating local addr cache")