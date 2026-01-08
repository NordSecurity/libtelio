import asyncio
import itertools
import pytest
from contextlib import AsyncExitStack
from scapy.layers.inet import TCP  # type: ignore
from scapy.layers.l2 import ARP  # type: ignore
from tests.helpers import (
    setup_api,
    setup_connections,
    SetupParameters,
    setup_mesh_nodes,
)
from tests.telio import Client
from tests.timeouts import TEST_BATCHING_TIMEOUT
from tests.utils.asyncio_util import run_async_context
from tests.utils.bindings import (
    default_features,
    features_with_endpoint_providers,
    FeatureLinkDetection,
    FeaturePersistentKeepalive,
    FeatureBatching,
    EndpointProvider,
    RelayState,
    NodeState,
    PathType,
    TelioAdapterType,
    LinkState,
)
from tests.utils.connection import ConnectionTag
from tests.utils.connection.docker_connection import (
    DockerConnection,
    container_id,
    DOCKER_GW_MAP,
)
from tests.utils.logger import log
from tests.utils.testing import log_test_passed
from tests.utils.traffic import (
    capture_traffic,
    render_chart,
    generate_packet_distribution_histogram,
    generate_packet_delay_histogram,
    get_ordered_histogram_score,
)
from typing import List

BATCHING_CAPTURE_TIME = 130
DOCKER_CONE_GW_2_IP = "10.0.254.2"


def _generate_setup_parameters(
    conn_tag: ConnectionTag, adapter: TelioAdapterType, batching: bool
) -> SetupParameters:
    features = features_with_endpoint_providers(
        [EndpointProvider.STUN, EndpointProvider.LOCAL]
    )
    features.link_detection = FeatureLinkDetection(
        rtt_seconds=1, use_for_downgrade=True
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
    (
        ConnectionTag.DOCKER_OPEN_INTERNET_CLIENT_1,
        TelioAdapterType.LINUX_NATIVE_TUN,
    ),
    (
        ConnectionTag.DOCKER_OPEN_INTERNET_CLIENT_2,
        TelioAdapterType.LINUX_NATIVE_TUN,
    ),
]


@pytest.mark.asyncio
@pytest.mark.timeout(TEST_BATCHING_TIMEOUT)
@pytest.mark.parametrize(
    "setup_params,capture_duration",
    [
        pytest.param(
            [
                _generate_setup_parameters(conn_tag, adapter, False)
                for conn_tag, adapter in ALL_NODES
            ],
            BATCHING_CAPTURE_TIME,
            marks=[
                pytest.mark.batching,
            ],
        ),
        pytest.param(
            [
                _generate_setup_parameters(conn_tag, adapter, True)
                for conn_tag, adapter in ALL_NODES
            ],
            BATCHING_CAPTURE_TIME,
            marks=[
                pytest.mark.batching,
            ],
        ),
    ],
)
async def test_batching(
    setup_params: List[SetupParameters],
    capture_duration: int,
) -> None:
    """Batch test generates environment where all peers idle after forming direct connections
    packet capture is being used to observe how traffic flows and is then processed and displayed.
    """

    async with AsyncExitStack() as exit_stack:
        api, nodes = setup_api(
            [(instance.is_local, instance.ip_stack) for instance in setup_params]
        )
        connection_managers = await setup_connections(
            exit_stack,
            [
                (
                    instance.connection_tag,
                    instance.connection_tracker_config,
                )
                for instance in setup_params
            ],
        )

        clients = []
        for node, conn_man, params in zip(nodes, connection_managers, setup_params):
            client = Client(
                conn_man.connection, node, params.adapter_type_override, params.features
            )
            clients.append(client)

        alpha_client, beta_client, *_ = clients

        # Start capture tasks

        # We capture the traffic from all nodes and gateways.
        # On gateways we are sure the traffic has left the machine, however no easy way to
        # inspect the packets(encrypted by wireguard). For packet inspection
        # client traffic can be inspected.
        gateways = [DOCKER_GW_MAP[param.connection_tag] for param in setup_params]
        gateway_container_names = [container_id(conn_tag) for conn_tag in gateways]
        conns = [client.get_connection() for client in clients]
        node_container_names = [
            container_id(conn.tag)
            for conn in conns
            if isinstance(conn, DockerConnection)
        ]

        container_names = sorted(
            list(set(gateway_container_names + node_container_names))
        )

        log.info("Will capture batching on containers: %s", container_names)
        pcap_capture_tasks = []
        for name in container_names:
            pcap_task = asyncio.create_task(
                capture_traffic(
                    name,
                    capture_duration,
                )
            )
            pcap_capture_tasks.append(pcap_task)

        async def delayed_task(delay, node, client):
            await asyncio.sleep(delay)
            return await exit_stack.enter_async_context(
                client.run(api.get_meshnet_config(node.id))
            )

        tasks = []
        for i, (client, node) in enumerate(zip(clients, nodes)):
            tasks.append(asyncio.create_task(delayed_task(i * 3, node, client)))

        # deliberately block direct connection alpha <-> beta. This will make alpha and beta still form direct connections with other peers
        # but alpha <-> beta itself will form after a delay causing misalignment which represents real world keepalive flow better
        async with AsyncExitStack() as exit_stack2:
            await exit_stack2.enter_async_context(
                alpha_client.get_router().disable_path(DOCKER_CONE_GW_2_IP),
            )
            await asyncio.sleep(20)

        await asyncio.gather(*[
            client.wait_for_state_on_any_derp([RelayState.CONNECTED])
            for client in [alpha_client, beta_client]
        ])

        await asyncio.gather(*[
            await exit_stack.enter_async_context(
                run_async_context(
                    client.wait_for_state_peer(
                        node.public_key, [NodeState.CONNECTED], [PathType.DIRECT]
                    )
                )
            )
            for client, node in itertools.product(clients, nodes)
            if not client.is_node(node)
        ])

        log.info("All peers directly interconnected")

        pyro5_ports = [
            int(port) for port in {client.get_proxy_port() for client in clients}
        ]

        log.info("Pyro ports %s", pyro5_ports)
        allow_pcap_filters = [
            (
                "No Pyro5 and no ARP",
                lambda p: (
                    (
                        (not p.haslayer(TCP))
                        or (
                            p.haslayer(TCP)
                            and p.sport not in pyro5_ports
                            and p.dport not in pyro5_ports
                        )
                    )
                    and (not p.haslayer(ARP))
                ),
            ),
        ]

        is_batching_enabled = clients[0].get_features().batching is not None

        pcap_paths = await asyncio.gather(*pcap_capture_tasks)
        for container, pcap_path in zip(container_names, pcap_paths):
            distribution_hs = generate_packet_distribution_histogram(
                pcap_path, capture_duration, allow_pcap_filters
            )
            delay_hs = generate_packet_delay_histogram(
                pcap_path, capture_duration, allow_pcap_filters
            )

            batch_str = "batch" if is_batching_enabled else "nobatch"

            log.info("*** %s-%s ***", container, batch_str)

            distribution_chart = render_chart(distribution_hs)
            delay_chart = render_chart(delay_hs)

            log.info("Distribution chart below")
            log.info(distribution_chart)

            log.info("Delay chart below")
            log.info(delay_chart)

            log.info("Score: %s", get_ordered_histogram_score(delay_hs))
        log_test_passed()


def proxying_peer_parameters(clients: List[ConnectionTag]):
    def features():
        features = default_features(enable_direct=False, enable_nurse=False)
        features.wireguard.persistent_keepalive.proxying = 5
        features.link_detection = FeatureLinkDetection(
            rtt_seconds=2, use_for_downgrade=False
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
        log_test_passed()
