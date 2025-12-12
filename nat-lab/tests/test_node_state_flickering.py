import asyncio
import itertools
import pytest
from contextlib import AsyncExitStack
from tests import timeouts
from tests.helpers import SetupParameters, setup_mesh_nodes
from tests.utils.bindings import (
    features_with_endpoint_providers,
    EndpointProvider,
    PathType,
    TelioAdapterType,
    NodeState,
    RelayState,
)
from tests.utils.connection import ConnectionTag
from tests.utils.connection_util import generate_connection_tracker_config


@pytest.mark.asyncio
@pytest.mark.timeout(timeouts.TEST_NODE_STATE_FLICKERING_RELAY_TIMEOUT)
@pytest.mark.long
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
            marks=pytest.mark.windows,
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
async def test_node_state_flickering_relay(
    alpha_setup_params: SetupParameters, beta_setup_params: SetupParameters
) -> None:
    async with AsyncExitStack() as exit_stack:
        env = await setup_mesh_nodes(
            exit_stack, [alpha_setup_params, beta_setup_params]
        )
        alpha, beta = env.nodes
        client_alpha, client_beta = env.clients

        with pytest.raises(asyncio.TimeoutError):
            await asyncio.gather(
                client_alpha.wait_for_event_peer(
                    beta.public_key, list(NodeState), timeout=120
                ),
                client_beta.wait_for_event_peer(
                    alpha.public_key, list(NodeState), timeout=120
                ),
                client_alpha.wait_for_event_on_any_derp(list(RelayState), timeout=120),
                client_beta.wait_for_event_on_any_derp(list(RelayState), timeout=120),
            )


CFG = [
    (TelioAdapterType.WINDOWS_NATIVE_TUN, [pytest.mark.windows]),
    (TelioAdapterType.NEP_TUN, []),
    (TelioAdapterType.LINUX_NATIVE_TUN, []),
]


@pytest.mark.long
@pytest.mark.timeout(timeouts.TEST_NODE_STATE_FLICKERING_DIRECT_TIMEOUT)
@pytest.mark.parametrize(
    "alpha_adapter_type,beta_adapter_type",
    [
        pytest.param(
            alpha_cfg[0],
            beta_cfg[0],
            marks=(
                [pytest.mark.windows2]
                if alpha_cfg[1] == [pytest.mark.windows]
                and beta_cfg[1] == [pytest.mark.windows]
                else alpha_cfg[1] + beta_cfg[1]
            ),
        )
        for alpha_cfg, beta_cfg in itertools.combinations_with_replacement(CFG, 2)
    ],
)
async def test_node_state_flickering_direct(
    alpha_adapter_type: TelioAdapterType,
    beta_adapter_type: TelioAdapterType,
) -> None:
    async with AsyncExitStack() as exit_stack:
        alpha_conn_tag = (
            ConnectionTag.VM_WINDOWS_1
            if alpha_adapter_type == TelioAdapterType.WINDOWS_NATIVE_TUN
            else ConnectionTag.DOCKER_CONE_CLIENT_1
        )
        beta_conn_tag = (
            ConnectionTag.VM_WINDOWS_2
            if beta_adapter_type == TelioAdapterType.WINDOWS_NATIVE_TUN
            else ConnectionTag.DOCKER_CONE_CLIENT_2
        )

        env = await setup_mesh_nodes(
            exit_stack,
            [
                SetupParameters(
                    connection_tag=alpha_conn_tag,
                    adapter_type_override=alpha_adapter_type,
                    features=features_with_endpoint_providers([
                        EndpointProvider.STUN,
                        EndpointProvider.LOCAL,
                        EndpointProvider.UPNP,
                    ]),
                ),
                SetupParameters(
                    connection_tag=beta_conn_tag,
                    adapter_type_override=beta_adapter_type,
                    features=features_with_endpoint_providers([
                        EndpointProvider.STUN,
                        EndpointProvider.LOCAL,
                        EndpointProvider.UPNP,
                    ]),
                ),
            ],
        )
        alpha, beta = env.nodes
        client_alpha, client_beta = env.clients

        with pytest.raises(asyncio.TimeoutError):
            await asyncio.gather(
                client_alpha.wait_for_event_peer(
                    beta.public_key,
                    list(NodeState),
                    list(PathType),
                    timeout=120,
                ),
                client_beta.wait_for_event_peer(
                    alpha.public_key,
                    list(NodeState),
                    list(PathType),
                    timeout=120,
                ),
                client_alpha.wait_for_event_on_any_derp(list(RelayState), timeout=120),
                client_beta.wait_for_event_on_any_derp(list(RelayState), timeout=120),
            )
