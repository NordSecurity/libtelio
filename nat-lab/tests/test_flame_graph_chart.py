import pytest
from tests import config
from tests.helpers import SetupParameters, Environment
from tests.helpers_vpn import VpnConfig
from tests.utils.bindings import TelioAdapterType
from tests.utils.connection import ConnectionTag
from tests.utils.logger import log
from tests.utils.ping import ping

pytest_plugins = ["tests.helpers_fixtures"]


# Module-level override — all tests in this file get VPN_1
@pytest.fixture(name="vpn_tags")
def _vpn_tags() -> list:
    return [ConnectionTag.DOCKER_VPN_1]


@pytest.mark.parametrize(
    "alpha_setup_params",
    [
        pytest.param(
            SetupParameters(
                connection_tag=ConnectionTag.DOCKER_CONE_CLIENT_1,
                adapter_type_override=TelioAdapterType.NEP_TUN,
                is_meshnet=False,
                run_tcpdump=False,
                enable_perf=True,
            ),
        ),
    ],
)
@pytest.mark.perf_profiling
@pytest.mark.asyncio
async def test_connect_node_flame_graph_chart(
    alpha_setup_params: SetupParameters,  # pylint: disable=unused-argument
    env: Environment,
) -> None:
    """
    Collect flame graph chart of connect_to_exit_node command

    Steps:
        1. Setup environment - create connections to nodes, create API client, mesh client
        2. Connect to vpn server
        3. Save perf command results
        4. Generate flame graph chart
        5. Save results to logs
    """
    alpha_client, alpha_conn = env.clients[0], env.connections[0].connection

    vpn_conf = VpnConfig(config.WG_SERVER, ConnectionTag.DOCKER_VPN_1, True)
    client_conn = alpha_conn
    client_alpha = alpha_client
    log.info("Connecting to vpn server")
    await client_alpha.connect_to_vpn(
        str(vpn_conf.server_conf["ipv4"]),
        int(vpn_conf.server_conf["port"]),
        str(vpn_conf.server_conf["public_key"]),
    )
    await ping(client_conn, config.PHOTO_ALBUM_IP)
