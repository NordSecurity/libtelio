import pytest
from contextlib import AsyncExitStack
from helpers import setup_mesh_nodes, SetupParameters
from utils.bindings import default_features, TelioAdapterType
from utils.connection_util import ConnectionTag
from utils.logger import log
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
async def test_measuring_link_speed(
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
        test_speed = 20
        await client_alpha.limit_network_speed(str(test_speed))
        await client_alpha.trigger_peer_link_speed_test(peer_ip)
        await client_alpha.wait_for_log("MiB/s Packet loss")
        speed = await client_alpha.fetch_peer_link_speed()
        await client_alpha.delete_limiter_rule()
        log.info("Got %d Expected %s", speed, test_speed)
        assert (
            test_speed * 0.8 < speed < test_speed * 1.2
        ), f"Expected {str(speed)} but got {test_speed}"

        await client_alpha.flush_logs()
        test_speed = 30
        await client_alpha.limit_network_speed(str(test_speed))
        await client_alpha.trigger_peer_link_speed_test(peer_ip)
        await client_alpha.wait_for_log("MiB/s Packet loss")
        speed = await client_alpha.fetch_peer_link_speed()
        await client_alpha.delete_limiter_rule()
        log.info("Got %d Expected %s", speed, test_speed)
        assert (
            test_speed * 0.8 < speed < test_speed * 1.2
        ), f"Expected {str(speed)} but got {test_speed}"
