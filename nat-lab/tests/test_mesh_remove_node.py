import asyncio
import pytest
from contextlib import AsyncExitStack
from tests.helpers import SetupParameters, setup_mesh_nodes
from tests.mesh_api import API
from tests.utils.bindings import TelioAdapterType
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
                    derp_1_limits=(1, 1),
                ),
            )
        ),
        pytest.param(
            SetupParameters(
                connection_tag=ConnectionTag.DOCKER_CONE_CLIENT_1,
                adapter_type_override=TelioAdapterType.LINUX_NATIVE_TUN,
                connection_tracker_config=generate_connection_tracker_config(
                    ConnectionTag.DOCKER_CONE_CLIENT_1,
                    derp_1_limits=(1, 1),
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
                    derp_1_limits=(1, 1),
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
                    derp_1_limits=(1, 1),
                ),
            ),
            marks=[
                pytest.mark.mac,
            ],
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
@pytest.mark.parametrize(
    "gamma_setup_params",
    [
        pytest.param(
            SetupParameters(
                connection_tag=ConnectionTag.DOCKER_SYMMETRIC_CLIENT_1,
                connection_tracker_config=generate_connection_tracker_config(
                    ConnectionTag.DOCKER_SYMMETRIC_CLIENT_1,
                    derp_1_limits=(1, 1),
                ),
            )
        )
    ],
)
async def test_mesh_remove_node(
    alpha_setup_params: SetupParameters,
    beta_setup_params: SetupParameters,
    gamma_setup_params: SetupParameters,
) -> None:
    async with AsyncExitStack() as exit_stack:
        api = API()

        (alpha, beta, gamma) = api.default_config_three_nodes()

        alpha.set_peer_firewall_settings(beta.id, allow_incoming_connections=False)
        beta.set_peer_firewall_settings(gamma.id, allow_incoming_connections=False)
        gamma.set_peer_firewall_settings(alpha.id, allow_incoming_connections=False)

        env = await setup_mesh_nodes(
            exit_stack,
            [alpha_setup_params, beta_setup_params, gamma_setup_params],
            provided_api=api,
        )

        connection_alpha, connection_beta, connection_gamma = [
            conn.connection for conn in env.connections
        ]
        client_alpha, client_beta, _ = env.clients

        await ping(connection_alpha, beta.ip_addresses[0])
        await ping(connection_beta, gamma.ip_addresses[0])
        await ping(connection_gamma, alpha.ip_addresses[0])

        api.remove(gamma.id)

        await client_alpha.set_meshnet_config(api.get_meshnet_config(alpha.id))
        await client_beta.set_meshnet_config(api.get_meshnet_config(beta.id))

        await ping(connection_alpha, beta.ip_addresses[0])
        with pytest.raises(asyncio.TimeoutError):
            await ping(connection_beta, gamma.ip_addresses[0], 5)
        with pytest.raises(asyncio.TimeoutError):
            await ping(connection_gamma, alpha.ip_addresses[0], 5)
        log_test_passed()
