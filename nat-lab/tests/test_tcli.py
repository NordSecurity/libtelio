from contextlib import AsyncExitStack
from mesh_api import API
from utils import ConnectionTag, new_connection_by_tag
import pytest
import telio
import utils.testing as testing


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "alpha_connection_tag, adapter_type",
    [
        pytest.param(
            ConnectionTag.DOCKER_CONE_CLIENT_1,
            telio.AdapterType.BoringTun,
        ),
        pytest.param(
            ConnectionTag.DOCKER_CONE_CLIENT_1,
            telio.AdapterType.LinuxNativeWg,
            marks=pytest.mark.linux_native,
        ),
        pytest.param(
            ConnectionTag.WINDOWS_VM,
            telio.AdapterType.WindowsNativeWg,
            marks=pytest.mark.windows,
        ),
        pytest.param(
            ConnectionTag.WINDOWS_VM,
            telio.AdapterType.WireguardGo,
            marks=pytest.mark.windows,
        ),
        pytest.param(
            ConnectionTag.MAC_VM,
            telio.AdapterType.Default,
            marks=pytest.mark.mac,
        ),
    ],
)
async def test_register_meshnet_client(
    alpha_connection_tag: ConnectionTag, adapter_type: telio.AdapterType
) -> None:
    async with AsyncExitStack() as exit_stack:
        api = API()

        alpha = api.register(
            name="alpha",
            id="96ddb926-4b86-11ec-81d3-0242ac130003",
            private_key="COFFL2gadYvMNw4aiJAvhbGlJ/F5W7+RdM3ZkSKbVmU=",
            public_key="YDDaDQHwFlzyQOFahY35KW9jUsan3TOkQ2ZuyErLBjY=",
        )

        beta = api.register(
            name="beta",
            id="7b4548ca-fe5a-4597-8513-896f38c6d6ae",
            private_key="gGsIZ/nk0tyeihKWdGvWg60mE97eGK8KRC238iHF+Wg=",
            public_key="hljyPueY/FgRVrhzDxviv7SDOtoYVUppCbb4uJiBQ3o=",
        )

        api.assign_ip(alpha.id, "100.64.0.11")
        api.assign_ip(beta.id, "100.64.0.22")

        client_alpha = await exit_stack.enter_async_context(
            telio.run_meshnet(
                await exit_stack.enter_async_context(
                    new_connection_by_tag(alpha_connection_tag)
                ),
                alpha,
                api.get_meshmap(alpha.id),
                adapter_type,
            )
        )

        client_beta = await exit_stack.enter_async_context(
            telio.run_meshnet(
                await exit_stack.enter_async_context(
                    new_connection_by_tag(ConnectionTag.DOCKER_CONE_CLIENT_2)
                ),
                beta,
                api.get_meshmap(beta.id),
            )
        )

        await testing.wait_long(client_alpha.handshake(beta.public_key))
        await testing.wait_long(client_beta.handshake(alpha.public_key))
