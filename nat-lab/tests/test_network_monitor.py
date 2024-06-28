import pytest
import time
from contextlib import AsyncExitStack
from helpers import setup_mesh_nodes, SetupParameters
from telio import AdapterType
from utils.connection_util import ConnectionTag

DEFAULT_WAITING_TIME = 2


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "alpha_setup_params",
    [
        pytest.param(
            SetupParameters(
                connection_tag=ConnectionTag.DOCKER_SHARED_CLIENT_1,
                adapter_type=AdapterType.BoringTun,
            )
        ),
        pytest.param(
            SetupParameters(
                connection_tag=ConnectionTag.WINDOWS_VM_1,
                adapter_type=AdapterType.WireguardGo,
            ),
            marks=[pytest.mark.windows],
        ),
        pytest.param(
            SetupParameters(
                connection_tag=ConnectionTag.MAC_VM,
                adapter_type=AdapterType.BoringTun,
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
        alpha_conn_mngr, *_ = env.connections
        [client_alpha] = env.clients

        assert alpha_conn_mngr.network_switcher

        result = await client_alpha.fetch_interfaces()
        assert len(result) == 2
        await exit_stack.enter_async_context(
            alpha_conn_mngr.network_switcher.add_secondary_ip()
        )
        time.sleep(DEFAULT_WAITING_TIME)
        result = await client_alpha.fetch_interfaces()
        await exit_stack.enter_async_context(
            alpha_conn_mngr.network_switcher.remove_secondary_ip()
        )
        assert len(result) == 3
