import pytest
from contextlib import AsyncExitStack
from helpers import setup_mesh_nodes, SetupParameters
from utils.bindings import default_features, TelioAdapterType
from utils.connection_util import ConnectionTag
from utils.router import IPProto


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "alpha_setup_params",
    [
        pytest.param(
            SetupParameters(
                connection_tag=ConnectionTag.DOCKER_CONE_CLIENT_1,
                adapter_type_override=TelioAdapterType.LINUX_NATIVE_TUN,
                features=default_features(enable_link_speed_test=True),
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
                features=default_features(enable_link_speed_test=True),
            ),
        ),
    ],
)
async def test_throughput_real(
    alpha_setup_params: SetupParameters,
    beta_setup_params: SetupParameters,
) -> None:
    async with AsyncExitStack() as exit_stack:
        env = await setup_mesh_nodes(
            exit_stack, [alpha_setup_params, beta_setup_params]
        )
        [_, beta] = env.nodes
        [client_alpha, _] = env.clients

        peer_ip = beta.get_ip_address(IPProto.IPv4)
        assert peer_ip is not None, "Expected a string, but got None"
        test_speed = 2
        await client_alpha.limit_network_speed(test_speed)
        await client_alpha.trigger_peer_link_speed_test(peer_ip)
        await client_alpha.wait_for_log("MiB/s Packet loss")
        speed = await client_alpha.fetch_peer_link_speed()
        await client_alpha.delete_limiter_rule()
        assert test_speed == speed


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "alpha_setup_params",
    [
        pytest.param(
            SetupParameters(
                connection_tag=ConnectionTag.DOCKER_CONE_CLIENT_1,
                adapter_type_override=TelioAdapterType.LINUX_NATIVE_TUN,
                features=default_features(enable_link_speed_test=True),
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
                features=default_features(enable_link_speed_test=True),
            ),
        ),
    ],
)
async def test_link_speed(
    alpha_setup_params: SetupParameters,
    beta_setup_params: SetupParameters,
) -> None:
    async with AsyncExitStack() as exit_stack:
        env = await setup_mesh_nodes(
            exit_stack, [alpha_setup_params, beta_setup_params]
        )
        [_, beta] = env.nodes
        [client_alpha, _] = env.clients

        peer_ip = beta.get_ip_address(IPProto.IPv4)
        assert peer_ip is not None, "Expected a string, but got None"

        await client_alpha.trigger_peer_link_speed_test(peer_ip)
        await client_alpha.wait_for_log("MiB/s Packet loss")
