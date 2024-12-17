import asyncio
import itertools
import pytest
from contextlib import AsyncExitStack
from helpers import SetupParameters, setup_environment, setup_mesh_nodes
from itertools import zip_longest
from scapy.layers.inet import TCP, UDP, ICMP  # type: ignore
from scapy.layers.l2 import ARP  # type: ignore
from timeouts import TEST_BATCHING_TIMEOUT
from typing import List
from utils.asyncio_util import run_async_context
from utils.bindings import (
    default_features,
    features_with_endpoint_providers,
    FeatureLinkDetection,
    FeaturePersistentKeepalive,
    FeatureBatching,
    EndpointProvider,
    RelayState,
    LinkState,
    NodeState,
    PathType,
    TelioAdapterType,
)
from utils.connection import DockerConnection
from utils.connection_util import ConnectionTag, DOCKER_GW_MAP, container_id
from utils.traffic import (
    capture_traffic,
    render_chart,
    generate_packet_distribution_histogram,
    generate_packet_delay_histogram,
)

BATCHING_MISALIGN_S = 7
BATCHING_CAPTURE_TIME = 120  # Tied to TEST_BATCHING_TIMEOUT


def _generate_setup_parameters(
    conn_tag: ConnectionTag, adapter: TelioAdapterType, batching: bool
) -> SetupParameters:
    features = features_with_endpoint_providers([EndpointProvider.STUN])

    features.link_detection = FeatureLinkDetection(
        rtt_seconds=1, no_of_pings=1, use_for_downgrade=True
    )
    features.batching = (
        FeatureBatching(
            direct_connection_threshold=15,
            trigger_effective_duration=10,
            trigger_cooldown_duration=60,
        )
        if batching
        else None
    )
    features.wireguard.persistent_keepalive = FeaturePersistentKeepalive(
        direct=30,
        proxying=30,
        stun=30,
        vpn=30,
    )

    return SetupParameters(
        connection_tag=conn_tag,
        adapter_type_override=adapter,
        features=features,
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
]
# This test captures histograms of network activity to evaluate the effect of local batching in libtelio.
# Since only local batching is implemented, no client-generated traffic should occur during the test.
# External traffic (incoming data) could distort the histograms, and receive-data-triggered batching is
# not yet supported in libtelio. The test setup is simple: all clients are interconnected and remain idle
# for an extended period. This idle period allows for a visual observation.
# Local batching will only have an effect of batching multiple local keepalives into one bundle but will
# not do anything about syncing the keepalives between the peers.


@pytest.mark.asyncio
@pytest.mark.timeout(TEST_BATCHING_TIMEOUT)
@pytest.mark.parametrize(
    "setup_params,misalign_sleep_s,capture_duration",
    [
        pytest.param(
            [
                _generate_setup_parameters(conn_tag, adapter, True)
                for conn_tag, adapter in ALL_NODES
            ],
            BATCHING_MISALIGN_S,
            BATCHING_CAPTURE_TIME,
            marks=[
                pytest.mark.batching,
            ],
        ),
        pytest.param(
            [
                _generate_setup_parameters(conn_tag, adapter, False)
                for conn_tag, adapter in ALL_NODES
            ],
            BATCHING_MISALIGN_S,
            BATCHING_CAPTURE_TIME,
            marks=[
                pytest.mark.batching,
            ],
        ),
    ],
)
async def test_batching(
    setup_params: List[SetupParameters],
    misalign_sleep_s: int,
    capture_duration: int,
) -> None:
    async with AsyncExitStack() as exit_stack:
        env = await exit_stack.enter_async_context(
            setup_environment(exit_stack, setup_params)
        )

        await asyncio.gather(*[
            client.wait_for_state_on_any_derp([RelayState.CONNECTED])
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
        async def start_node_manually(client, node, sleep_s):
            await asyncio.sleep(sleep_s)
            await client.simple_start()
            await client.set_meshnet_config(env.api.get_meshnet_config(node.id))

        await asyncio.gather(*[
            start_node_manually(client, node, i * misalign_sleep_s)
            for i, (client, node) in enumerate(cnodes)
        ])

        await asyncio.gather(*[
            await exit_stack.enter_async_context(
                run_async_context(
                    client.wait_for_state_peer(
                        node.public_key, [NodeState.CONNECTED], [PathType.DIRECT]
                    )
                )
            )
            for client, node in itertools.product(env.clients, env.nodes)
            if not client.is_node(node)
        ])

        pyro5_ports = [
            int(port) for port in {client.get_proxy_port() for client in env.clients}
        ]

        print("Pyro ports", pyro5_ports)
        # In general it's not great to filter traffic but for testing and observing
        # it's crucial since it distorts the results. For example Pyro traffic is a constant stream of
        # TCP packets
        allow_pcap_filters = [
            (
                "No Pyro5, SSDP, ARP",
                lambda p: (
                    (
                        (p.haslayer(UDP) or p.haslayer(TCP))
                        and p.sport not in pyro5_ports
                        and p.dport not in pyro5_ports
                    )
                    and (
                        not p.haslayer(ICMP)
                        or p.haslayer(ICMP)
                        and p[ICMP].type in [0, 8]
                    )
                    and (
                        p.haslayer(UDP)
                        and p[UDP].sport != 1900
                        and p[UDP].dport != 1900
                    )
                    and (not p.haslayer(ARP))
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

        is_batching_enabled = env.clients[0].get_features().batching is not None
        for container, pcap_path in zip(container_names, pcap_paths):
            distribution_hs = generate_packet_distribution_histogram(
                pcap_path, capture_duration, allow_pcap_filters
            )
            delay_hs = generate_packet_delay_histogram(
                pcap_path, capture_duration, allow_pcap_filters
            )

            batch_str = "batch" if is_batching_enabled else "nobatch"

            print(f"*** {container}-{batch_str} ***")

            distribution_chart = render_chart(distribution_hs)
            delay_chart = render_chart(delay_hs)

            print("Distribution chart below")
            print(distribution_chart)

            print("Delay chart below")
            print(delay_chart)


def proxying_peer_parameters(clients: List[ConnectionTag]):
    def features():
        features = default_features(enable_direct=False, enable_nurse=False)
        features.wireguard.persistent_keepalive.proxying = 5
        features.link_detection = FeatureLinkDetection(
            rtt_seconds=2, no_of_pings=0, use_for_downgrade=False
        )

        features.batching = FeatureBatching(
            direct_connection_threshold=5,
            trigger_cooldown_duration=60,
            trigger_effective_duration=10,
        )
        return features

    return [
        SetupParameters(
            connection_tag=conn_tag,
            adapter_type_override=TelioAdapterType.NEP_TUN,
            features=features(),
            fingerprint=f"{conn_tag}",
        )
        for conn_tag in clients
    ]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "setup_params",
    [
        proxying_peer_parameters(
            [ConnectionTag.DOCKER_CONE_CLIENT_1, ConnectionTag.DOCKER_CONE_CLIENT_2]
        )
    ],
)
async def test_proxying_peer_batched_keepalive(
    setup_params: List[SetupParameters],
) -> None:
    # Since batching keepalives are performed on application level instead of Wireguard
    # backend we need to ensure that proxying peers are receiving the keepalives. To test
    # for that we can enable link detection that guarantees quick detection if there's no corresponding
    # received traffic(WireGuard PassiveKeepalive). If batcher correctly emits pings, it
    # should trigger link detection quite quickly.
    async with AsyncExitStack() as exit_stack:
        env = await setup_mesh_nodes(exit_stack, setup_params)

        await asyncio.gather(*[
            await exit_stack.enter_async_context(
                run_async_context(
                    client.wait_for_state_peer(
                        node.public_key, [NodeState.CONNECTED], [PathType.RELAY]
                    )
                )
            )
            for client, node in itertools.product(env.clients, env.nodes)
            if not client.is_node(node)
        ])

        alpha, beta = env.clients
        await beta.stop_device()

        _, beta_node = env.nodes

        await alpha.wait_for_state_peer(
            beta_node.public_key,
            [NodeState.CONNECTED],
            [PathType.RELAY],
            timeout=30,
            link_state=LinkState.DOWN,
        )
