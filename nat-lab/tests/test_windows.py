import pytest
import aiodocker
import utils.testing as testing
from contextlib import AsyncExitStack
from utils import container_util, windows_vm_util
from mesh_api import API
import telio


@pytest.mark.windows
@pytest.mark.asyncio
async def test_windows_telio() -> None:
    async with AsyncExitStack() as exit_stack:
        api = API()

        alpha = api.register(
            name="alpha",
            id="96ddb926-4b86-11ec-81d3-0242ac130003",
            private_key="COFFL2gadYvMNw4aiJAvhbGlJ/F5W7+RdM3ZkSKbVmU=",
            public_key="YDDaDQHwFlzyQOFahY35KW9jUsan3TOkQ2ZuyErLBjY=",
        )
        api.assign_ip(alpha.id, "100.64.0.11")

        beta = api.register(
            name="beta",
            id="7b4548ca-fe5a-4597-8513-896f38c6d6ae",
            private_key="gGsIZ/nk0tyeihKWdGvWg60mE97eGK8KRC238iHF+Wg=",
            public_key="hljyPueY/FgRVrhzDxviv7SDOtoYVUppCbb4uJiBQ3o=",
        )
        api.assign_ip(beta.id, "100.64.0.22")

        connection_alpha = await exit_stack.enter_async_context(
            windows_vm_util.new_connection()
        )
        docker = await exit_stack.enter_async_context(aiodocker.Docker())

        client_alpha = await exit_stack.enter_async_context(
            telio.run(connection_alpha, alpha)
        )
        await client_alpha.set_meshmap(api.get_meshmap(alpha.id))

        client_beta = await exit_stack.enter_async_context(
            telio.run_meshnet(
                await container_util.get(docker, "nat-lab-cone-client-02-1"),
                beta,
                api.get_meshmap(beta.id),
            )
        )

        await testing.wait_long(client_alpha.handshake(beta.public_key))
        await testing.wait_long(client_beta.handshake(alpha.public_key))
