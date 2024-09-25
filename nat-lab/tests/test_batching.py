import asyncio
import pytest
import random
from contextlib import AsyncExitStack
from helpers import SetupParameters, setup_environment
from itertools import zip_longest
from scapy.layers.inet import TCP, UDP  # type: ignore
from timeouts import TEST_BATCHING_TIMEOUT
from typing import List, Tuple, Any
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
    RelayState,
    TelioAdapterType,
)
from utils.connection import DockerConnection
from utils.connection_util import DOCKER_GW_MAP, ConnectionTag, container_id

BATCHING_MISALIGN_RANGE = (0, 3)  # Seconds to sleep for peers before starting
BATCHING_CAPTURE_TIME = 30  # Tied to TEST_BATCHING_TIMEOUT


def _generate_setup_parameters(
    conn_tag: ConnectionTag, adapter: TelioAdapterType, batching: bool
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
        connection_tag=conn_tag, adapter_type_override=adapter, features=features
    )


ALL_NODES = [
    (
        ConnectionTag.DOCKER_CONE_CLIENT_1,
        TelioAdapterType.LINUX_NATIVE_TUN,
    ),
    (
        ConnectionTag.DOCKER_CONE_CLIENT_2,
        TelioAdapterType.LINUX_NATIVE_TUN,
    ),
    (
        ConnectionTag.DOCKER_SYMMETRIC_CLIENT_1,
        TelioAdapterType.LINUX_NATIVE_TUN,
    ),
    (
        ConnectionTag.DOCKER_SYMMETRIC_CLIENT_2,
        TelioAdapterType.LINUX_NATIVE_TUN,
    ),
    (
        ConnectionTag.DOCKER_UPNP_CLIENT_1,
        TelioAdapterType.LINUX_NATIVE_TUN,
    ),
    (
        ConnectionTag.DOCKER_UPNP_CLIENT_2,
        TelioAdapterType.LINUX_NATIVE_TUN,
    ),
    (
        ConnectionTag.DOCKER_SHARED_CLIENT_1,
        TelioAdapterType.LINUX_NATIVE_TUN,
    ),
    (
        ConnectionTag.DOCKER_OPEN_INTERNET_CLIENT_1,
        TelioAdapterType.LINUX_NATIVE_TUN,
    ),
    (
        ConnectionTag.DOCKER_OPEN_INTERNET_CLIENT_2,
        TelioAdapterType.LINUX_NATIVE_TUN,
    ),
    (
        ConnectionTag.DOCKER_OPEN_INTERNET_CLIENT_DUAL_STACK,
        TelioAdapterType.LINUX_NATIVE_TUN,
    ),
    (
        ConnectionTag.DOCKER_UDP_BLOCK_CLIENT_1,
        TelioAdapterType.LINUX_NATIVE_TUN,
    ),
    (
        ConnectionTag.DOCKER_UDP_BLOCK_CLIENT_2,
        TelioAdapterType.LINUX_NATIVE_TUN,
    ),
    (
        ConnectionTag.DOCKER_INTERNAL_SYMMETRIC_CLIENT,
        TelioAdapterType.LINUX_NATIVE_TUN,
    ),
    (ConnectionTag.DOCKER_FULLCONE_CLIENT_1, TelioAdapterType.LINUX_NATIVE_TUN),
    (ConnectionTag.DOCKER_FULLCONE_CLIENT_2, TelioAdapterType.LINUX_NATIVE_TUN),
    (
        ConnectionTag.MAC_VM,
        TelioAdapterType.BORING_TUN,
    ),
    (ConnectionTag.WINDOWS_VM_1, TelioAdapterType.WINDOWS_NATIVE_TUN),
    (ConnectionTag.WINDOWS_VM_2, TelioAdapterType.WIREGUARD_GO_TUN),
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
        # We capture the traffic from all nodes and gateways.
        # On gateways we are sure the traffic has left the machine, however no easy way to
        # inspect the packets(encrypted by wireguard). For packet inspection
        # client traffic can be inspected.
        env = await exit_stack.enter_async_context(
            setup_environment(exit_stack, setup_params)
        )

        gateways = [DOCKER_GW_MAP[param.connection_tag] for param in setup_params]
        gateway_container_names = [container_id(conn_tag) for conn_tag in gateways]
        conns = [client.get_connection() for client in env.clients]
        node_container_names = [
            conn.container_name()
            for conn in conns
            if isinstance(conn, DockerConnection)
        ]

        container_names = gateway_container_names + node_container_names
        print("Will capture traffic on containers: ", container_names)

        pcap_capture_tasks: List[Any] = []
        for name in container_names:
            pcap_task = asyncio.create_task(
                capture_traffic(
                    name,
                    capture_duration,
                )
            )
            pcap_capture_tasks.append(pcap_task)

        # at this point packet captures are running
        await asyncio.gather(*[
            client.wait_for_state_on_any_derp([RelayState.CONNECTED])
            for client, instance in zip_longest(env.clients, setup_params)
            if instance.derp_servers != []
        ])

        # At this stage all peers have been started and connected to DERP server meaning they are ready.
        # It's a good time to misalign the peers by stopping all of them and then sleeping for random amounts
        # of time in parallel before starting again. This gives a more realistic view as when peer comes online,
        # it's added to other peers meshmaps and misalignment occurs naturally since peers already were online.
        # In NatLab all peers start at more or less the same time normally, preventing batching to do anything useful.
        for client in env.clients:
            await client.stop_device()

        async def start_node_manually(client, node, sleep_min: int, sleep_max: int):
            await asyncio.sleep(random.randint(sleep_min, sleep_max))
            await client.simple_start()
            await client.set_meshnet_config(env.api.get_meshnet_config(node.id))

        cnodes = zip(env.clients, env.nodes)
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

        await asyncio.gather(*[
            client.wait_for_state_on_any_derp([RelayState.CONNECTED])
            for client, instance in zip_longest(env.clients, setup_params)
            if instance.derp_servers != []
        ])

        pcap_paths: list[str] = await asyncio.gather(*pcap_capture_tasks)

        # Once capture tasks end, we reached the end of the test
        for container, pcap_path in zip(container_names, pcap_paths):
            for filt in allow_pcap_filters:
                filter_name = filt[0]
                hs = generate_histogram_from_pcap(pcap_path, capture_duration, filt[1])
                title = f"{container}-filter({filter_name})"
                print_histogram(title, hs, max_height=12)

        # In the end, the histograms are captured that can now be used for observing the results
