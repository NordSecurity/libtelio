import asyncio
import pytest
import time
from telio import AdapterType
from contextlib import AsyncExitStack
from helpers import (
    setup_mesh_nodes,
    SetupParameters,
)
from utils.connection_util import ConnectionTag
import re
from utils.asyncio_util import run_async_context
DEFAULT_WAITING_TIME = 5

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
        env = await setup_mesh_nodes(
            exit_stack, [alpha_setup_params]
        )
        alpha_conn_mngr, *_ = env.connections
        [client_alpha] = env.clients

        assert alpha_conn_mngr.network_switcher

        await asyncio.sleep(DEFAULT_WAITING_TIME)
        intreface_event = client_alpha.wait_for_output("Local interfaces:")
        await client_alpha.fetch_interfaces()
        await intreface_event.wait()
        result = re.search(r"Local interfaces:: (.*)", client_alpha.get_stdout())
        print(result)
        intreface_event.clear()
        async with alpha_conn_mngr.network_switcher.switch_to_secondary_network():
            await client_alpha.notify_network_change()
        time.sleep(DEFAULT_WAITING_TIME)
        intreface_event = client_alpha.wait_for_output("Local interfaces:")
        await client_alpha.fetch_interfaces()
        await intreface_event.wait()
        result = re.search(r"Local interfaces:: (.*)", client_alpha.get_stdout())
        print(result)
