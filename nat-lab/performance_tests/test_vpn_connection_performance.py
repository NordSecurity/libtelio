import json
import os
import pytest
from contextlib import AsyncExitStack
from dataclasses import asdict
from tests import config
from tests.helpers import SetupParameters, setup_environment
from tests.helpers_vpn import connect_vpn, VpnConfig
from tests.utils.bindings import TelioAdapterType
from tests.utils.connection import Connection, ConnectionTag
from tests.utils.connection_util import new_connection_raw, new_connection_by_tag
from tests.utils.iperf3 import (
    IperfServer,
    IperfClient,
    Protocol,
    UploadMetrics,
    DownloadMetrics,
    ThroughputUnit,
)
from tests.utils.logger import log
from tests.utils.testing import get_current_test_log_path


async def collect_upload_metrics(
    server_connection: Connection,
    client_connection: Connection,
    transmit_time: int = 20,
    output_unit: ThroughputUnit = ThroughputUnit.KILOBITS,
) -> UploadMetrics:
    """
    This function starts an iperf3 TCP server on `server_connection`,
    then starts an iperf3 TCP client on `client_connection` which sends
    traffic to the configured PHOTO_ALBUM_IP server for a specified
    duration. After the test completes, the function parses the iperf3
    JSON results and extracts:

        - Upload speed (in the chosen unit, e.g. Kbits/Mbits/Gbits)
        - Number of TCP retransmissions
        - RTT statistics: min, max, mean (in milliseconds)

    Parameters
    ----------
    server_connection : Connection
        The connection object used to start the iperf3 server process.
    client_connection : Connection
        The connection object used to start the iperf3 client process.
    transmit_time : int, optional
        Duration of the iperf3 test, in seconds (default: 20).
    output_unit : ThroughputUnit, optional
        Unit for throughput values passed to iperf3's `-f` flag.

    Returns
    -------
    UploadMetrics
        containing:
            upload_speed : float
                Upload speed in the chosen unit (e.g., Mbits/sec).
            retransmits : int
                Number of TCP retransmissions reported by iperf3 JSON.
            min_rtt : float
                Minimum RTT in milliseconds.
            max_rtt : float
                Maximum RTT in milliseconds.
            mean_rtt : float
                Mean RTT in milliseconds.
            transmitted_packets: int
                Number of transmitted packets.

    Raises
    ------
    AssertionError
        If iperf3 output cannot be parsed.
    Exception
        If JSON parsing is attempted without JSON output enabled.
    """
    server = IperfServer(
        connection=server_connection,
        log_prefix="server",
        verbose=True,
        protocol=Protocol.Tcp,
    )
    client = IperfClient(
        server_ip=config.PHOTO_ALBUM_IP,
        connection=client_connection,
        log_prefix="client",
        transmit_time=transmit_time,
        buf_length="128K",
        verbose=True,
        protocol=Protocol.Tcp,
        output_unit=output_unit,
        json_output=True,
    )
    async with server.run():
        await server.listening_started()
        async with client.run():
            await client.done()

    upload_speed = client.get_speed()
    log.info("Upload Speed: %s %s/sec", upload_speed, output_unit.unit_string())
    retransmits = client.get_retransmits()
    log.info("Retransmits: %s", retransmits)
    min_rtt, max_rtt, mean_rtt = client.get_rtt_stats()
    log.info("RTT: %s, %s, %s", min_rtt, max_rtt, mean_rtt)
    transmitted_packets = client.get_transmitted_packets()
    log.info("Transmitted Packets: %s", transmitted_packets)
    return UploadMetrics(
        upload_speed=upload_speed,
        retransmits=retransmits,
        min_rtt=min_rtt,
        max_rtt=max_rtt,
        mean_rtt=mean_rtt,
        transmitted_packets=transmitted_packets,
    )


async def collect_download_metrics(
    server_connection: Connection,
    client_connection: Connection,
    transmit_time: int = 20,
    output_unit: ThroughputUnit = ThroughputUnit.KILOBITS,
) -> DownloadMetrics:
    """
    This function starts an iperf3 TCP server, then starts an iperf3
    TCP client in reverse mode (`-R`) so that the server sends data
    to the client. After the test completes, the function parses the
    iperf3 JSON results and extracts the download speed.

    Parameters
    ----------
    server_connection : Connection
        The connection object used to start the iperf3 server process.
    client_connection : Connection
        The connection object used to start the iperf3 client process.
    transmit_time : int, optional
        Duration of the iperf3 test, in seconds (default: 20).
    output_unit : ThroughputUnit, optional
        Unit for throughput values passed to iperf3's `-f` flag.

    Returns
    -------
    DownloadMetrics
        Download speed in the chosen unit (e.g., Mbits/sec).

    Raises
    ------
    AssertionError
        If iperf3 output cannot be parsed.
    Exception
        If JSON parsing is attempted without JSON output enabled.
    """
    server = IperfServer(
        connection=server_connection,
        log_prefix="server",
        verbose=True,
        protocol=Protocol.Tcp,
    )
    client = IperfClient(
        server_ip=config.PHOTO_ALBUM_IP,
        connection=client_connection,
        log_prefix="client",
        transmit_time=transmit_time,
        buf_length="128K",
        verbose=True,
        protocol=Protocol.Tcp,
        send=False,
        output_unit=output_unit,
        json_output=True,
    )
    async with server.run():
        await server.listening_started()
        async with client.run():
            await client.done()
    download_speed = client.get_speed()
    log.info("Download Speed: %s %s/sec", download_speed, output_unit.unit_string())
    return DownloadMetrics(download_speed=download_speed)


@pytest.mark.asyncio
async def test_vpn_connection_performance() -> None:
    """
    Collect performance metrics of vpn connection with iperf

    Steps:
        1. Setup environment - create connections to nodes, create API client, mesh client
        2. Run speed tests without vpn connection  - collecting baseline results
        3. Connect to vpn server
        4. Run speed tests with vpn connection
        5. Save performance results
    """
    async with AsyncExitStack() as exit_stack:
        # Setup environment
        setup_params = SetupParameters(
            connection_tag=ConnectionTag.DOCKER_CONE_CLIENT_1,
            adapter_type_override=TelioAdapterType.NEP_TUN,
            is_meshnet=False,
            run_tcpdump=False,
        )
        vpn_conf = VpnConfig(config.WG_SERVER, ConnectionTag.DOCKER_VPN_1, True)
        env = await exit_stack.enter_async_context(
            setup_environment(exit_stack, [setup_params])
        )

        alpha, *_ = env.nodes
        client_conn, *_ = [conn.connection for conn in env.connections]
        client_alpha, *_ = env.clients
        vpn_connection = await exit_stack.enter_async_context(
            new_connection_by_tag(ConnectionTag.DOCKER_VPN_1)
        )
        photo_album_connection = await exit_stack.enter_async_context(
            new_connection_raw(ConnectionTag.DOCKER_PHOTO_ALBUM)
        )

        # Collecting baseline results without vpn connection
        performance_results = {}

        upload_metrics = await collect_upload_metrics(
            photo_album_connection, client_conn, output_unit=ThroughputUnit.MEGABITS
        )
        download_metrics = await collect_download_metrics(
            photo_album_connection, client_conn, output_unit=ThroughputUnit.MEGABITS
        )
        baseline_metrics = {
            **asdict(upload_metrics),
            **asdict(download_metrics),
        }
        performance_results["baseline_metrics"] = baseline_metrics

        # Connect to vpn server
        await env.api.prepare_vpn_servers([vpn_connection])
        await connect_vpn(
            client_conn,
            None,
            client_alpha,
            alpha.ip_addresses[0],
            vpn_conf.server_conf,
        )

        # Collecting performance results with connected vpn
        upload_metrics_vpn = await collect_upload_metrics(
            photo_album_connection, client_conn, output_unit=ThroughputUnit.MEGABITS
        )
        download_metrics_vpn = await collect_download_metrics(
            photo_album_connection, client_conn, output_unit=ThroughputUnit.MEGABITS
        )
        vpn_metrics = {
            **asdict(upload_metrics_vpn),
            **asdict(download_metrics_vpn),
        }
        performance_results["vpn_metrics"] = vpn_metrics
        log.info("Final results: %s", performance_results)

        # Saving performance results
        log_dir = get_current_test_log_path()
        os.makedirs(log_dir, exist_ok=True)
        results_path = os.path.join(log_dir, "performance_results.json")
        with open(results_path, "w", encoding="utf-8") as f:
            json.dump(performance_results, f, indent=4)
