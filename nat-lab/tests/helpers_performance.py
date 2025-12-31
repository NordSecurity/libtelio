import json
import os
from contextlib import AsyncExitStack
from dataclasses import asdict
from typing import Any, Dict

from tests import config
from tests.helpers import SetupParameters, setup_environment
from tests.utils.bindings import TelioAdapterType, NodeState, PathType
from tests.utils.connection import Connection, ConnectionTag
from tests.utils.iperf3 import (
    IperfServer,
    IperfClient,
    Protocol,
    UploadMetrics,
    DownloadMetrics,
    ThroughputUnit,
)
from tests.utils.logger import log
from tests.utils.ping import Ping
from tests.utils.testing import get_current_test_log_path


async def verify_ping_connectivity(
    connection: Connection, target_ip: str, timeout: float = 10
) -> None:
    """
    Verify connectivity with a simple ping test.

    Args:
        connection: Connection to ping from
        target_ip: Target IP address to ping
        timeout: Timeout in seconds for the ping test
    """
    async with Ping(connection, target_ip).run() as ping_proc:
        await ping_proc.wait_for_any_ping(timeout=timeout)


async def save_results_to_json(filename: str, results: Dict[str, Any]) -> None:
    """
    Save performance test results to a JSON file.

    Args:
        filename: Name of the JSON file to create
        results: Dictionary containing test results
    """
    log_dir = get_current_test_log_path()
    os.makedirs(log_dir, exist_ok=True)
    results_path = os.path.join(log_dir, filename)
    with open(results_path, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=4)


async def setup_two_node_meshnet(
    exit_stack: AsyncExitStack,
    adapter_type: TelioAdapterType = TelioAdapterType.NEP_TUN,
    client1_tag: ConnectionTag = ConnectionTag.DOCKER_CONE_CLIENT_1,
    client2_tag: ConnectionTag = ConnectionTag.DOCKER_CONE_CLIENT_2,
):
    """
    Setup a standard two-node meshnet environment.

    Args:
        exit_stack: AsyncExitStack for managing the environment lifecycle
        adapter_type: Type of adapter to use (BoringTun, Linux Native, NepTUN)
        client1_tag: Connection tag for the first client
        client2_tag: Connection tag for the second client

    Returns:
        Environment object with nodes, clients, and connections
    """
    setup_params = [
        SetupParameters(
            connection_tag=client1_tag,
            adapter_type_override=adapter_type,
            is_meshnet=True,
        ),
        SetupParameters(
            connection_tag=client2_tag,
            adapter_type_override=adapter_type,
            is_meshnet=True,
        ),
    ]
    return await exit_stack.enter_async_context(
        setup_environment(exit_stack, setup_params)
    )


async def run_iperf_test(
    server_connection: Connection,
    client_connection: Connection,
    server_ip: str,
    transmit_time: int,
    output_unit: ThroughputUnit,
    send: bool = True,
) -> IperfClient:
    """
    Run a single iperf3 test (upload or download).

    Args:
        server_connection: Connection for the iperf server
        client_connection: Connection for the iperf client
        server_ip: IP address of the server
        transmit_time: Duration of the test in seconds
        output_unit: Unit for throughput measurement
        send: True for upload test, False for download test

    Returns:
        IperfClient instance with test results
    """
    server = IperfServer(
        connection=server_connection,
        log_prefix="server",
        verbose=True,
        protocol=Protocol.Tcp,
    )
    client = IperfClient(
        server_ip=server_ip,
        connection=client_connection,
        log_prefix="client",
        transmit_time=transmit_time,
        buf_length="128K",
        verbose=True,
        protocol=Protocol.Tcp,
        send=send,
        output_unit=output_unit,
        json_output=True,
    )
    async with server.run():
        await server.listening_started()
        async with client.run():
            await client.done()

    return client


async def collect_throughput_metrics(
    server_connection: Connection,
    client_connection: Connection,
    server_ip: str,
    transmit_time: int = 20,
    output_unit: ThroughputUnit = ThroughputUnit.MEGABITS,
) -> tuple[UploadMetrics, DownloadMetrics]:
    """
    Collect upload and download throughput metrics between two connections.

    Args:
        server_connection: Connection for the iperf server
        client_connection: Connection for the iperf client
        server_ip: IP address of the server
        transmit_time: Duration of each test in seconds
        output_unit: Unit for throughput measurement

    Returns:
        Tuple of (upload_metrics, download_metrics)
    """
    # Upload test
    upload_client = await run_iperf_test(
        server_connection,
        client_connection,
        server_ip,
        transmit_time,
        output_unit,
        send=True,
    )

    upload_speed = upload_client.get_speed()
    retransmits = upload_client.get_retransmits()
    min_rtt, max_rtt, mean_rtt = upload_client.get_rtt_stats()

    upload_metrics = UploadMetrics(
        upload_speed=upload_speed,
        retransmits=retransmits,
        min_rtt=min_rtt,
        max_rtt=max_rtt,
        mean_rtt=mean_rtt,
    )

    # Download test
    download_client = await run_iperf_test(
        server_connection,
        client_connection,
        server_ip,
        transmit_time,
        output_unit,
        send=False,
    )

    download_speed = download_client.get_speed()
    download_metrics = DownloadMetrics(download_speed=download_speed)

    log.info(
        "Throughput - Upload: %s %s/sec, Download: %s %s/sec, RTT: %s/%s/%s ms, Retransmits: %s",
        upload_speed,
        output_unit.unit_string(),
        download_speed,
        output_unit.unit_string(),
        min_rtt,
        max_rtt,
        mean_rtt,
        retransmits,
    )

    return upload_metrics, download_metrics


async def measure_path_performance(
    client_alpha,
    beta_public_key: str,
    conn_alpha: Connection,
    conn_beta: Connection,
    beta_ip: str,
    path_type: PathType,
    transmit_time: int = 15,
    timeout: int = 30,
) -> Dict[str, Any]:
    """
    Measure performance metrics for a specific path type (RELAY or DIRECT).

    Args:
        client_alpha: Telio client instance
        beta_public_key: Public key of the peer
        conn_alpha: Connection for client alpha
        conn_beta: Connection for client beta
        beta_ip: IP address of beta
        path_type: Type of path to measure (RELAY or DIRECT)
        transmit_time: Duration of throughput tests in seconds
        timeout: Timeout for connection establishment

    Returns:
        Dictionary with upload_metrics, download_metrics, and path_type
    """
    log.info("Waiting for %s connection", path_type.name)
    await client_alpha.wait_for_state_peer(
        beta_public_key, [NodeState.CONNECTED], [path_type], timeout=timeout
    )

    log.info("Connected via %s, measuring performance", path_type.name)

    upload_metrics, download_metrics = await collect_throughput_metrics(
        conn_beta, conn_alpha, beta_ip, transmit_time=transmit_time
    )

    await verify_ping_connectivity(conn_alpha, beta_ip)

    return {
        "upload_metrics": asdict(upload_metrics),
        "download_metrics": asdict(download_metrics),
        "path_type": path_type.name,
    }


def calculate_performance_improvement(
    baseline: UploadMetrics | DownloadMetrics,
    improved: UploadMetrics | DownloadMetrics,
    metric_name: str,
) -> float:
    """
    Calculate percentage improvement between two metrics.

    Args:
        baseline: Baseline metrics object
        improved: Improved metrics object
        metric_name: Name of the attribute to compare

    Returns:
        Percentage improvement (positive means improved is better)
    """
    baseline_value = getattr(baseline, metric_name)
    improved_value = getattr(improved, metric_name)
    if baseline_value > 0:
        return (improved_value - baseline_value) / baseline_value * 100
    return 0.0


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
    return UploadMetrics(
        upload_speed=upload_speed,
        retransmits=retransmits,
        min_rtt=min_rtt,
        max_rtt=max_rtt,
        mean_rtt=mean_rtt,
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