import asyncio
import pytest
from contextlib import AsyncExitStack
from tests.helpers import setup_mesh_nodes, SetupParameters
from tests.utils import asyncio_util
from tests.utils.bindings import NodeState, RelayState, TelioAdapterType
from tests.utils.connection import ConnectionTag
from tests.utils.connection_util import generate_connection_tracker_config
from tests.utils.ping import ping
from tests.utils.testing import log_test_passed


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "alpha_setup_params",
    [
        pytest.param(
            SetupParameters(
                connection_tag=ConnectionTag.DOCKER_CONE_CLIENT_1,
                adapter_type_override=TelioAdapterType.NEP_TUN,
                connection_tracker_config=generate_connection_tracker_config(
                    ConnectionTag.DOCKER_CONE_CLIENT_1,
                    derp_1_limits=(1, 2),
                ),
            )
        ),
        pytest.param(
            SetupParameters(
                connection_tag=ConnectionTag.DOCKER_CONE_CLIENT_1,
                adapter_type_override=TelioAdapterType.LINUX_NATIVE_TUN,
                connection_tracker_config=generate_connection_tracker_config(
                    ConnectionTag.DOCKER_CONE_CLIENT_1,
                    derp_1_limits=(1, 2),
                ),
            ),
            marks=pytest.mark.linux_native,
        ),
        pytest.param(
            SetupParameters(
                connection_tag=ConnectionTag.VM_WINDOWS_1,
                adapter_type_override=TelioAdapterType.WINDOWS_NATIVE_TUN,
                connection_tracker_config=generate_connection_tracker_config(
                    ConnectionTag.VM_WINDOWS_1,
                    derp_1_limits=(1, 2),
                ),
            ),
            marks=[
                pytest.mark.windows,
            ],
        ),
        pytest.param(
            SetupParameters(
                connection_tag=ConnectionTag.VM_MAC,
                adapter_type_override=TelioAdapterType.NEP_TUN,
                connection_tracker_config=generate_connection_tracker_config(
                    ConnectionTag.VM_MAC,
                    derp_1_limits=(1, 2),
                ),
            ),
            marks=pytest.mark.mac,
        ),
    ],
)
@pytest.mark.parametrize(
    "beta_setup_params",
    [
        pytest.param(
            SetupParameters(
                connection_tag=ConnectionTag.DOCKER_CONE_CLIENT_2,
                connection_tracker_config=generate_connection_tracker_config(
                    ConnectionTag.DOCKER_CONE_CLIENT_2,
                    derp_1_limits=(1, 1),
                ),
            )
        )
    ],
)
async def test_mesh_reconnect(
    alpha_setup_params: SetupParameters, beta_setup_params: SetupParameters
) -> None:
    async with AsyncExitStack() as exit_stack:
        env = await setup_mesh_nodes(
            exit_stack, [alpha_setup_params, beta_setup_params]
        )
        api = env.api
        alpha, beta = env.nodes
        alpha_connection, beta_connection = [
            conn.connection for conn in env.connections
        ]
        client_alpha, client_beta = env.clients

        await ping(alpha_connection, beta.ip_addresses[0])
        await ping(beta_connection, alpha.ip_addresses[0])

        await client_alpha.stop_device()

        with pytest.raises(asyncio.TimeoutError):
            await ping(beta_connection, alpha.ip_addresses[0], 15)

        await client_alpha.simple_start()

        async with asyncio_util.run_async_context(
            asyncio.gather(
                client_alpha.wait_for_event_peer(
                    beta.public_key, [NodeState.CONNECTED]
                ),
                client_alpha.wait_for_event_on_any_derp([RelayState.CONNECTED]),
            ),
        ) as event:
            await client_alpha.set_meshnet_config(api.get_meshnet_config(alpha.id))
            await event

        await asyncio.gather(
            client_alpha.wait_for_state_peer(beta.public_key, [NodeState.CONNECTED]),
            client_beta.wait_for_state_peer(alpha.public_key, [NodeState.CONNECTED]),
        )

        await ping(alpha_connection, beta.ip_addresses[0])
        await ping(beta_connection, alpha.ip_addresses[0])
        log_test_passed()
