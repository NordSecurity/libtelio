import asyncio
import time
import pytest
from contextlib import AsyncExitStack
from dataclasses import asdict
from typing import Any, Dict
from tests.helpers_performance import (
    collect_throughput_metrics,
    save_results_to_json,
    setup_two_node_meshnet,
    verify_ping_connectivity,
    measure_path_performance,
    calculate_performance_improvement,
)
from tests.helpers import SetupParameters, setup_environment
from tests.utils.bindings import TelioAdapterType, NodeState, PathType
from tests.utils.connection import ConnectionTag
from tests.utils.iperf3 import UploadMetrics, DownloadMetrics
from tests.utils.logger import log


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "adapter_type",
    [
        pytest.param(
            TelioAdapterType.BORING_TUN,
            marks=pytest.mark.linux_native,
        ),
        pytest.param(
            TelioAdapterType.LINUX_NATIVE_TUN,
            marks=pytest.mark.linux_native,
        ),
        pytest.param(
            TelioAdapterType.NEP_TUN,
            marks=pytest.mark.linux_native,
        ),
    ],
)
async def test_meshnet_adapter_performance(adapter_type: TelioAdapterType) -> None:
    """
    Test meshnet performance with different adapter types.

    Compares performance across:
    - BoringTun (userspace WireGuard)
    - Linux Native TUN (kernel WireGuard)
    - NepTUN (optimized adapter)

    Steps:
        1. Setup two-node meshnet with specified adapter
        2. Measure throughput and latency
        3. Save results for comparison
    """
    async with AsyncExitStack() as exit_stack:
        env = await setup_two_node_meshnet(exit_stack, adapter_type)

        _, beta = env.nodes
        client_alpha, _ = env.clients
        conn_alpha, conn_beta = [conn.connection for conn in env.connections]

        # Wait for meshnet connection
        await client_alpha.wait_for_state_peer(
            beta.public_key, [NodeState.CONNECTED], timeout=30
        )

        # Collect performance metrics
        upload_metrics, download_metrics = await collect_throughput_metrics(
            conn_beta, conn_alpha, beta.ip_addresses[0]
        )

        # Verify connectivity
        log.info("Testing ping connectivity")
        await verify_ping_connectivity(conn_alpha, beta.ip_addresses[0])

        results: Dict[str, Any] = {
            "adapter_type": adapter_type.name,
            "upload_metrics": asdict(upload_metrics),
            "download_metrics": asdict(download_metrics),
        }

        log.info("Adapter %s results: %s", adapter_type.name, results)

        await save_results_to_json(
            f"adapter_performance_{adapter_type.name}.json", results
        )


@pytest.mark.asyncio
async def test_relay_vs_direct_performance() -> None:
    """
    Compare performance of relay connection vs direct P2P connection.

    Tests the performance difference between:
    - Relay connection (through DERP server)
    - Direct P2P connection (after upgrade)

    Steps:
        1. Setup two-node meshnet
        2. Measure performance over relay
        3. Force/wait for P2P upgrade
        4. Measure performance over direct connection
        5. Compare results
    """
    async with AsyncExitStack() as exit_stack:
        env = await setup_two_node_meshnet(exit_stack)

        _, beta = env.nodes
        client_alpha, _ = env.clients
        conn_alpha, conn_beta = [conn.connection for conn in env.connections]

        results: Dict[str, Any] = {}

        # Phase 1: Measure relay performance
        log.info("Phase 1: Testing relay connection performance")
        relay_data = await measure_path_performance(
            client_alpha,
            beta.public_key,
            conn_alpha,
            conn_beta,
            beta.ip_addresses[0],
            PathType.RELAY,
        )
        upload_relay = UploadMetrics(**relay_data["upload_metrics"])
        download_relay = DownloadMetrics(**relay_data["download_metrics"])
        results["relay"] = relay_data

        # Phase 2: Measure direct P2P performance
        log.info("Phase 2: Waiting for P2P upgrade")
        direct_data = await measure_path_performance(
            client_alpha,
            beta.public_key,
            conn_alpha,
            conn_beta,
            beta.ip_addresses[0],
            PathType.DIRECT,
            timeout=60,
        )
        upload_direct = UploadMetrics(**direct_data["upload_metrics"])
        download_direct = DownloadMetrics(**direct_data["download_metrics"])
        results["direct_p2p"] = direct_data

        # Calculate improvements
        results["comparison"] = {
            "upload_improvement_percent": calculate_performance_improvement(
                upload_relay, upload_direct, "upload_speed"
            ),
            "download_improvement_percent": calculate_performance_improvement(
                download_relay, download_direct, "download_speed"
            ),
            "rtt_improvement_ms": upload_relay.mean_rtt - upload_direct.mean_rtt,
            "rtt_improvement_percent": calculate_performance_improvement(
                upload_direct, upload_relay, "mean_rtt"
            ),
        }

        log.info("Relay vs Direct comparison: %s", results["comparison"])

        await save_results_to_json("relay_vs_direct_performance.json", results)


@pytest.mark.asyncio
async def test_connection_upgrade_time() -> None:
    """
    Measure time taken for relay connection to upgrade to direct P2P.

    Steps:
        1. Setup two-node meshnet
        2. Establish initial relay connection
        3. Measure time to P2P upgrade
        4. Record upgrade metrics
    """
    async with AsyncExitStack() as exit_stack:
        env = await setup_two_node_meshnet(exit_stack)

        _, beta = env.nodes
        client_alpha, _ = env.clients

        # Start timing
        start_time = time.time()

        # Wait for initial connection (relay)
        await client_alpha.wait_for_state_peer(
            beta.public_key, [NodeState.CONNECTED], [PathType.RELAY], timeout=30
        )
        relay_connection_time = time.time() - start_time

        log.info("Relay connection established in %.2f seconds", relay_connection_time)

        # Wait for P2P upgrade
        upgrade_start = time.time()
        await client_alpha.wait_for_state_peer(
            beta.public_key, [NodeState.CONNECTED], [PathType.DIRECT], timeout=60
        )

        upgrade_time = time.time() - upgrade_start
        total_time = time.time() - start_time

        results = {
            "relay_connection_time_seconds": relay_connection_time,
            "upgrade_time_seconds": upgrade_time,
            "total_time_seconds": total_time,
            "initial_path_type": "RELAY",
            "final_path_type": "DIRECT",
        }

        log.info("Connection upgrade metrics: %s", results)

        await save_results_to_json("connection_upgrade_time.json", results)


@pytest.mark.asyncio
async def test_multi_peer_meshnet_performance() -> None:
    """
    Test meshnet performance with multiple peers.

    Measures performance degradation (if any) when multiple peers
    are connected simultaneously.

    Steps:
        1. Setup 3-node meshnet
        2. Measure pairwise performance between all nodes
        3. Compare with 2-node baseline
    """
    async with AsyncExitStack() as exit_stack:
        setup_params = [
            SetupParameters(
                connection_tag=ConnectionTag.DOCKER_CONE_CLIENT_1,
                adapter_type_override=TelioAdapterType.NEP_TUN,
                is_meshnet=True,
            ),
            SetupParameters(
                connection_tag=ConnectionTag.DOCKER_CONE_CLIENT_2,
                adapter_type_override=TelioAdapterType.NEP_TUN,
                is_meshnet=True,
            ),
            SetupParameters(
                connection_tag=ConnectionTag.DOCKER_OPEN_INTERNET_CLIENT_1,
                adapter_type_override=TelioAdapterType.NEP_TUN,
                is_meshnet=True,
            ),
        ]

        env = await exit_stack.enter_async_context(
            setup_environment(exit_stack, setup_params)
        )

        _, beta, gamma = env.nodes
        client_alpha, client_beta, _ = env.clients
        conn_alpha, conn_beta, conn_gamma = [
            conn.connection for conn in env.connections
        ]

        # Wait for all connections
        await asyncio.gather(
            client_alpha.wait_for_state_peer(
                beta.public_key, [NodeState.CONNECTED], timeout=30
            ),
            client_alpha.wait_for_state_peer(
                gamma.public_key, [NodeState.CONNECTED], timeout=30
            ),
            client_beta.wait_for_state_peer(
                gamma.public_key, [NodeState.CONNECTED], timeout=30
            ),
        )

        results: Dict[str, Any] = {}

        # Test alpha -> beta
        log.info("Testing alpha -> beta")
        upload_ab, download_ab = await collect_throughput_metrics(
            conn_beta, conn_alpha, beta.ip_addresses[0], transmit_time=10
        )

        results["alpha_to_beta"] = {
            "upload_metrics": asdict(upload_ab),
            "download_metrics": asdict(download_ab),
        }

        # Test alpha -> gamma
        log.info("Testing alpha -> gamma")
        upload_ag, download_ag = await collect_throughput_metrics(
            conn_gamma, conn_alpha, gamma.ip_addresses[0], transmit_time=10
        )

        results["alpha_to_gamma"] = {
            "upload_metrics": asdict(upload_ag),
            "download_metrics": asdict(download_ag),
        }

        # Test beta -> gamma
        log.info("Testing beta -> gamma")
        upload_bg, download_bg = await collect_throughput_metrics(
            conn_gamma, conn_beta, gamma.ip_addresses[0], transmit_time=10
        )

        results["beta_to_gamma"] = {
            "upload_metrics": asdict(upload_bg),
            "download_metrics": asdict(download_bg),
        }

        log.info("Multi-peer meshnet results: %s", results)

        await save_results_to_json("multi_peer_meshnet_performance.json", results)
