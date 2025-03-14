import pytest
from contextlib import AsyncExitStack
from helpers import setup_mesh_nodes, SetupParameters
from utils.bindings import TelioAdapterType
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
            ),
        ),
    ],
)
async def test_throughput(
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
        await client_alpha.trigger_throughput_test(get_str(peer_ip))

        await client_alpha.wait_for_log("MiB/s Packet loss")


def get_str(value: str | None) -> str:  # type: ignore
    if value is None:
        raise TypeError("Expected a string, but got None")
    return value
