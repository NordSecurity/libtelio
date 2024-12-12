import pytest
from contextlib import AsyncExitStack
from helpers import setup_mesh_nodes, SetupParameters
from utils.bindings import default_features, TelioAdapterType
from utils.connection_util import ConnectionTag
from utils.logger import log
from utils.router import IPProto


@pytest.mark.asyncio
@pytest.mark.perf
@pytest.mark.parametrize(
    "test_speed",
    [
        pytest.param(2),
        pytest.param(20),
        pytest.param(80),
    ],
)
async def test_measuring_link_speed(test_speed: int) -> None:
    async with AsyncExitStack() as exit_stack:
        env = await setup_mesh_nodes(
            exit_stack,
            [
                SetupParameters(
                    connection_tag=ConnectionTag.DOCKER_CONE_CLIENT_1,
                    adapter_type_override=TelioAdapterType.LINUX_NATIVE_TUN,
                    features=default_features(enable_link_speed_test=True),
                ),
                SetupParameters(
                    connection_tag=ConnectionTag.DOCKER_CONE_CLIENT_2,
                    adapter_type_override=TelioAdapterType.LINUX_NATIVE_TUN,
                    features=default_features(enable_link_speed_test=True),
                ),
            ],
            download_pcaps=False,
        )
        [_, beta] = env.nodes
        [client_alpha, _] = env.clients

        peer_ip = beta.get_ip_address(IPProto.IPv4)
        assert peer_ip is not None, "Expected a string, but got None"
        await client_alpha.limit_network_speed(str(test_speed))
        await client_alpha.trigger_peer_link_speed_test(peer_ip)
        await client_alpha.wait_for_log("Mbps Packet loss")
        speed = await client_alpha.try_fetch_peer_link_speed()
        await client_alpha.delete_limiter_rule()
        log.info("Got %d Mbps Expected %s Mbps", speed, test_speed)
        assert (
            test_speed * 0.8 <= speed <= test_speed * 1.2
        ), f"Expected {test_speed} Mbps but got {str(speed)} Mbps"
