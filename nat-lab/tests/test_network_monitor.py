import asyncio
import pytest
from contextlib import AsyncExitStack
from helpers import setup_mesh_nodes, SetupParameters
from utils.bindings import TelioAdapterType
from utils.connection import ConnectionTag

DEFAULT_WAITING_TIME = 2


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "alpha_setup_params",
    [
        pytest.param(
            SetupParameters(
                connection_tag=ConnectionTag.DOCKER_SHARED_CLIENT_1,
                adapter_type_override=TelioAdapterType.NEP_TUN,
            ),
        ),
        pytest.param(
            SetupParameters(
                connection_tag=ConnectionTag.VM_MAC,
                adapter_type_override=TelioAdapterType.NEP_TUN,
            ),
            marks=[
                pytest.mark.mac,
                pytest.mark.xfail(reason="Expected failure on mac, see LLT-6728"),
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
        await client_alpha.wait_for_log(
            "Detected network interface modification, notifying..",
            count=4,
            not_greater=True,
        )
