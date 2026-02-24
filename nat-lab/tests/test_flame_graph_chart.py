import pytest
from contextlib import AsyncExitStack
from tests import config
from tests.helpers import SetupParameters, setup_environment
from tests.helpers_vpn import VpnConfig
from tests.utils.bindings import TelioAdapterType
from tests.utils.connection import ConnectionTag
from tests.utils.logger import log
from tests.utils.ping import ping


@pytest.mark.perf_profiling
@pytest.mark.asyncio
async def test_connect_node_flame_graph_chart() -> None:
    """
    Collect flame graph chart of connect_to_exit_node command

    Steps:
        1. Setup environment - create connections to nodes, create API client, mesh client
        2. Connect to vpn server
        3. Save perf command results
        4. Generate flame graph chart
        5. Save results to logs
    """
    async with AsyncExitStack() as exit_stack:
        # Setup environment
        setup_params = SetupParameters(
            connection_tag=ConnectionTag.DOCKER_CONE_CLIENT_1,
            adapter_type_override=TelioAdapterType.NEP_TUN,
            is_meshnet=False,
            run_tcpdump=False,
            enable_perf=True,
        )
        vpn_conf = VpnConfig(config.WG_SERVER, ConnectionTag.DOCKER_VPN_1, True)
        log.info("Creating connection to nodes")
        env = await exit_stack.enter_async_context(
            setup_environment(exit_stack, [setup_params], vpn=[vpn_conf.conn_tag])
        )

        client_conn, *_ = [conn.connection for conn in env.connections]
        client_alpha, *_ = env.clients
        log.info("Connecting to vpn server")
        await client_alpha.connect_to_vpn(
            str(vpn_conf.server_conf["ipv4"]),
            int(vpn_conf.server_conf["port"]),
            str(vpn_conf.server_conf["public_key"]),
        )
        await ping(client_conn, config.PHOTO_ALBUM_IP)
