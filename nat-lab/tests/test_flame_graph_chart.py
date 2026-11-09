import pytest
from tests import config
from tests.helpers import SetupParameters, Environment
from tests.helpers_vpn import VpnConfig
from tests.utils.bindings import TelioAdapterType
from tests.utils.connection import Connection, ConnectionTag
from tests.utils.connection_util import new_connection_raw
from tests.utils.iperf3 import IperfClient, IperfServer, Protocol
from tests.utils.logger import log
from tests.utils.perf_profiling import PERF_ROUNDS_PATH
from tests.utils.ping import ping

ROUNDS = 10
ROUND_SECONDS = 10
IPERF_BITRATE = "200M"  # fixed, below the tunnel's limit on the slowest runner
CONNECT_CYCLES = 20


async def _monotonic(conn: Connection) -> str:
    p = await conn.create_process(
        ["python3", "-c", "import time; print(time.monotonic())"], quiet=True
    ).execute()
    return p.get_stdout().strip()


async def _mark_round(conn: Connection, start: str, end: str) -> None:
    await conn.create_process(
        ["sh", "-c", f"echo '{start} {end}' >> {PERF_ROUNDS_PATH}"]
    ).execute()


async def _reset_rounds(conn: Connection) -> None:
    await conn.create_process(["rm", "-f", PERF_ROUNDS_PATH]).execute()


async def _iperf(conn: Connection, seconds: int) -> None:
    client = IperfClient(
        server_ip=config.PHOTO_ALBUM_IP,
        connection=conn,
        log_prefix="client",
        transmit_time=seconds,
        buf_length="1200",  # fits the tunnel MTU without IP fragmentation
        protocol=Protocol.Udp,
        bitrate=IPERF_BITRATE,
    )
    async with client.run():
        await client.done()


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
            id="neptun",
        ),
        pytest.param(
            SetupParameters(
                connection_tag=ConnectionTag.DOCKER_CONE_CLIENT_1,
                adapter_type_override=TelioAdapterType.LINUX_NATIVE_TUN,
                is_meshnet=False,
                run_tcpdump=False,
                enable_perf=True,
            ),
            marks=[pytest.mark.linux_native],
            id="linux_native",
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
        2. Connect to / disconnect from vpn server CONNECT_CYCLES times, each cycle is a round
        3. Save perf command results (whole run + one folded file per round)
        4. Generate flame graph chart
        5. Save results to logs
    """
    alpha_client, alpha_conn = env.clients[0], env.connections[0].connection

    vpn_conf = VpnConfig(config.WG_SERVER, ConnectionTag.DOCKER_VPN_1, True)
    client_conn = alpha_conn
    client_alpha = alpha_client
    public_key = str(vpn_conf.server_conf["public_key"])
    await _reset_rounds(client_conn)
    for cycle in range(CONNECT_CYCLES):
        log.info("Connect cycle %d/%d", cycle + 1, CONNECT_CYCLES)
        start = await _monotonic(client_conn)
        await client_alpha.vpn.connect(
            str(vpn_conf.server_conf["ipv4"]),
            int(vpn_conf.server_conf["port"]),
            public_key,
        )
        await ping(client_conn, config.PHOTO_ALBUM_IP)
        await client_alpha.vpn.disconnect(public_key)
        await _mark_round(client_conn, start, await _monotonic(client_conn))


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
            id="neptun",
        ),
    ],
)
@pytest.mark.perf_profiling
@pytest.mark.asyncio
async def test_data_transfer_flame_graph_chart(
    alpha_setup_params: SetupParameters,  # pylint: disable=unused-argument
    env: Environment,
) -> None:
    """
    Collect flame graph chart of fixed-bitrate UDP traffic through the VPN tunnel

    Steps:
        1. Setup environment and connect to vpn server
        2. Run a short iperf3 warm-up (not recorded)
        3. Run ROUNDS iperf3 rounds of ROUND_SECONDS at IPERF_BITRATE, marking each round
        4. Save perf results (whole run + one folded file per round)
    """
    client_alpha, client_conn = env.clients[0], env.connections[0].connection

    vpn_conf = VpnConfig(config.WG_SERVER, ConnectionTag.DOCKER_VPN_1, True)
    await client_alpha.vpn.connect(
        str(vpn_conf.server_conf["ipv4"]),
        int(vpn_conf.server_conf["port"]),
        str(vpn_conf.server_conf["public_key"]),
    )
    await ping(client_conn, config.PHOTO_ALBUM_IP)
    await _reset_rounds(client_conn)

    async with new_connection_raw(ConnectionTag.DOCKER_PHOTO_ALBUM) as album:
        server = IperfServer(album, "server", protocol=Protocol.Udp)
        async with server.run():
            await server.listening_started()
            # warm-up, not recorded as a round
            await _iperf(client_conn, seconds=3)
            for i in range(ROUNDS):
                log.info("Data transfer round %d/%d", i + 1, ROUNDS)
                start = await _monotonic(client_conn)
                await _iperf(client_conn, seconds=ROUND_SECONDS)
                await _mark_round(client_conn, start, await _monotonic(client_conn))
