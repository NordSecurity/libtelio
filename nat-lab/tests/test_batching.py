import asyncio
import pytest
import random
import telio
from contextlib import AsyncExitStack
from helpers import SetupParameters, setup_environment
from itertools import zip_longest
from scapy.layers.inet import TCP, UDP  # type: ignore
from telio import State, AdapterType
from timeouts import TEST_BATCHING_TIMEOUT
from typing import List, Tuple
from utils.batching import (
    capture_traffic,
    print_histogram,
    generate_histogram_from_pcap,
)
from utils.bindings import (
    features_with_endpoint_providers,
    FeatureLinkDetection,
    FeaturePersistentKeepalive,
    FeatureBatching,
    EndpointProvider,
)
from utils.connection import DockerConnection
from utils.connection_util import DOCKER_GW_MAP, ConnectionTag, container_id

BATCHING_MISALIGN_RANGE = (0, 5)  # Seconds to sleep for peers before starting
BATCHING_CAPTURE_TIME = 240  # Tied to TEST_BATCHING_TIMEOUT


def _generate_setup_parameters(
    conn_tag: ConnectionTag, adapter: telio.AdapterType, batching: bool
) -> SetupParameters:
    features = features_with_endpoint_providers(
        [EndpointProvider.UPNP, EndpointProvider.LOCAL, EndpointProvider.STUN]
    )

    features.link_detection = FeatureLinkDetection(
        rtt_seconds=1, no_of_pings=1, use_for_downgrade=True
    )
    features.batching = (
        FeatureBatching(direct_connection_threshold=35) if batching else None
    )
    features.wireguard.persistent_keepalive = FeaturePersistentKeepalive(
        direct=70,
        proxying=70,
        stun=70,
        vpn=70,
    )

    return SetupParameters(
        connection_tag=conn_tag,
        adapter_type=adapter,
        features=features,
    )


ALL_NODES = [
    (
        ConnectionTag.DOCKER_CONE_CLIENT_1,
        AdapterType.LinuxNativeWg,
    ),
    (
        ConnectionTag.DOCKER_CONE_CLIENT_2,
        AdapterType.LinuxNativeWg,
    ),
    (
        ConnectionTag.DOCKER_SYMMETRIC_CLIENT_1,
        AdapterType.LinuxNativeWg,
    ),
    (
        ConnectionTag.DOCKER_SYMMETRIC_CLIENT_2,
        AdapterType.LinuxNativeWg,
    ),
    (
        ConnectionTag.DOCKER_UPNP_CLIENT_1,
        AdapterType.LinuxNativeWg,
    ),
    (
        ConnectionTag.DOCKER_UPNP_CLIENT_2,
        AdapterType.LinuxNativeWg,
    ),
    (
        ConnectionTag.DOCKER_SHARED_CLIENT_1,
        AdapterType.LinuxNativeWg,
    ),
    (
        ConnectionTag.DOCKER_OPEN_INTERNET_CLIENT_1,
        AdapterType.LinuxNativeWg,
    ),
    (
        ConnectionTag.DOCKER_OPEN_INTERNET_CLIENT_2,
        AdapterType.LinuxNativeWg,
    ),
    (
        ConnectionTag.DOCKER_OPEN_INTERNET_CLIENT_DUAL_STACK,
        AdapterType.LinuxNativeWg,
    ),
    (
        ConnectionTag.DOCKER_UDP_BLOCK_CLIENT_1,
        AdapterType.LinuxNativeWg,
    ),
    (
        ConnectionTag.DOCKER_UDP_BLOCK_CLIENT_2,
        AdapterType.LinuxNativeWg,
    ),
    (
        ConnectionTag.DOCKER_INTERNAL_SYMMETRIC_CLIENT,
        AdapterType.LinuxNativeWg,
    ),
    (ConnectionTag.DOCKER_FULLCONE_CLIENT_1, AdapterType.LinuxNativeWg),
    (ConnectionTag.DOCKER_FULLCONE_CLIENT_2, AdapterType.LinuxNativeWg),
    (
        ConnectionTag.MAC_VM,
        AdapterType.BoringTun,
    ),
    (ConnectionTag.WINDOWS_VM_1, AdapterType.WindowsNativeWg),
    (ConnectionTag.WINDOWS_VM_2, AdapterType.WireguardGo),
]
# This test captures histograms of network activity to evaluate the effect of local batching in libtelio.
# Since only local batching is implemented, no client-generated traffic should occur during the test.
# External traffic (incoming data) could distort the histograms, and receive-data-triggered batching is
# not yet supported in libtelio. The test setup is simple: all clients are interconnected and remain idle
# for an extended period. This idle period allows for a visual observation.
# Local batching will only have an effect of batching multiple local keepalives into one bundle but will
# not do anything about syncing the keepalives between the peers.


# TODO: Add asserts for local batching
# TODO: Implement received-data-trigger batching
@pytest.mark.asyncio
@pytest.mark.timeout(TEST_BATCHING_TIMEOUT)
@pytest.mark.parametrize(
    "setup_params,misalign_sleep_range,capture_duration",
    [
        pytest.param(
            [
                _generate_setup_parameters(conn_tag, adapter, False)
                for conn_tag, adapter in ALL_NODES
            ],
            BATCHING_MISALIGN_RANGE,
            BATCHING_CAPTURE_TIME,
            marks=[
                pytest.mark.batching,
                pytest.mark.mac,
                pytest.mark.windows,
            ],
        ),
        pytest.param(
            [
                _generate_setup_parameters(conn_tag, adapter, True)
                for conn_tag, adapter in ALL_NODES
            ],
            BATCHING_MISALIGN_RANGE,
            BATCHING_CAPTURE_TIME,
            marks=[
                pytest.mark.batching,
                pytest.mark.mac,
                pytest.mark.windows,
            ],
        ),
    ],
)
async def test_batching(
    setup_params: List[SetupParameters],
    misalign_sleep_range: Tuple[int, int],
    capture_duration: int,
) -> None:
    async with AsyncExitStack() as exit_stack:
        env = await exit_stack.enter_async_context(
            setup_environment(exit_stack, setup_params)
        )

        await asyncio.gather(*[
            client.wait_for_state_on_any_derp([State.Connected])
            for client, instance in zip_longest(env.clients, setup_params)
            if instance.derp_servers != []
        ])

        # We capture the traffic from all nodes and gateways.
        # On gateways we are sure the traffic has left the machine, however no easy way to
        # inspect the packets(encrypted by wireguard). For packet inspection
        # client traffic can be inspected.
        gateways = [DOCKER_GW_MAP[param.connection_tag] for param in setup_params]
        gateway_container_names = [container_id(conn_tag) for conn_tag in gateways]
        conns = [client.get_connection() for client in env.clients]
        node_container_names = [
            conn.container_name()
            for conn in conns
            if isinstance(conn, DockerConnection)
        ]

        container_names = gateway_container_names + node_container_names
        print("Will capture batching on containers: ", container_names)
        cnodes = zip(env.clients, env.nodes)

        # Misalign the peers by first stopping all of them and then restarting after various delays.
        # This will have an effect of forcing neighboring libtelio node to add the peer to internal lists
        # for keepalives at various points in time thus allowing us to observe better
        # if the local batching is in action.
        for client in env.clients:
            await client.stop_device()

        # misalign the peers by sleeping some before starting each node again
        async def start_node_manually(client, node, sleep_min: int, sleep_max: int):
            await asyncio.sleep(random.randint(sleep_min, sleep_max))
            await client.simple_start()
            await client.set_meshmap(env.api.get_meshmap(node.id))

        await asyncio.gather(*[
            start_node_manually(
                client, node, misalign_sleep_range[0], misalign_sleep_range[1]
            )
            for client, node in cnodes
        ])

        pyro5_ports = [
            int(port) for port in {client.get_proxy_port() for client in env.clients}
        ]

        allow_pcap_filters = [
            (
                "IP46 + No Pyro5 traffic",
                lambda p: (
                    (p.haslayer(UDP) or p.haslayer(TCP))
                    and p.sport not in pyro5_ports
                    and p.dport not in pyro5_ports
                ),
            ),
        ]

        pcap_capture_tasks = []
        for name in container_names:
            pcap_task = asyncio.create_task(
                capture_traffic(
                    name,
                    capture_duration,
                )
            )
            pcap_capture_tasks.append(pcap_task)

        pcap_paths = await asyncio.gather(*pcap_capture_tasks)

        for container, pcap_path in zip(container_names, pcap_paths):
            for filt in allow_pcap_filters:
                filter_name = filt[0] if filt else "none"
                hs = generate_histogram_from_pcap(
                    pcap_path, capture_duration, filt[1] if filt else None
                )
                title = f"{container}-filter({filter_name})"
                print_histogram(title, hs, max_height=12)
