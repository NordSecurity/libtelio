# Packet captures and histograms are used to visually and in-code observe the batching in action.
import asyncio
import os
import pytest
import telio
from contextlib import AsyncExitStack
from helpers import setup_mesh_nodes, SetupParameters
from itertools import product
from scapy.layers.inet import IP, UDP  # type: ignore
from scapy.layers.inet6 import ICMPv6EchoRequest, IPv6  # type: ignore
from telio import PathType, State, AdapterType
from telio_features import (
    Batching,
    LinkDetection,
    PersistentKeepalive,
    TelioFeatures,
    Direct,
    Wireguard,
)
from typing import List
from utils.batching import capture_traffic, save_histogram, generate_histogram_from_pcap
from utils.connection import DockerConnection
from utils.connection_util import DOCKER_GW_MAP, ConnectionTag, container_id


def _generate_setup_parameters(
    conn_tag: ConnectionTag,
    adapter: telio.AdapterType,
    endpoint_providers: List[str],
    direct_enabled: bool,
    batching_enabled: bool,
) -> SetupParameters:
    features = TelioFeatures(
        direct=Direct(providers=endpoint_providers) if direct_enabled else None,
        link_detection=LinkDetection(
            use_for_downgrade=True, rtt_seconds=1, no_of_pings=1
        ),
        wireguard=Wireguard(
            persistent_keepalive=PersistentKeepalive(
                direct=70,
                proxying=70,
                stun=70,
                vpn=70,
            )
        ),
        batching=Batching(direct_connection_threshold=35) if batching_enabled else None,
    )

    item = SetupParameters(
        connection_tag=conn_tag,
        adapter_type=adapter,
        features=features,
    )

    return item


@pytest.mark.batching
@pytest.mark.asyncio
@pytest.mark.timeout(200)
@pytest.mark.parametrize(
    "setup_params,misalign_sleep_amount",
    [
        pytest.param(
            [
                _generate_setup_parameters(
                    ConnectionTag.DOCKER_CONE_CLIENT_1,
                    AdapterType.LinuxNativeWg,
                    ["stun", "upnp", "local"],
                    direct_enabled=True,
                    batching_enabled=True,
                ),
                _generate_setup_parameters(
                    ConnectionTag.DOCKER_CONE_CLIENT_2,
                    AdapterType.LinuxNativeWg,
                    ["stun", "upnp", "local"],
                    direct_enabled=True,
                    batching_enabled=True,
                ),
                _generate_setup_parameters(
                    ConnectionTag.DOCKER_UPNP_CLIENT_1,
                    AdapterType.LinuxNativeWg,
                    ["stun", "upnp", "local"],
                    direct_enabled=True,
                    batching_enabled=True,
                ),
                _generate_setup_parameters(
                    ConnectionTag.DOCKER_UPNP_CLIENT_2,
                    AdapterType.LinuxNativeWg,
                    ["stun", "upnp", "local"],
                    direct_enabled=True,
                    batching_enabled=True,
                ),
            ],
            6,
            marks=[pytest.mark.small_batch],
        ),
    ],
)
async def test_batching_star(
    setup_params: List[SetupParameters], misalign_sleep_amount: int
) -> None:
    async with AsyncExitStack() as exit_stack:
        capture_duration = 100

        env = await setup_mesh_nodes(exit_stack, setup_params)

        await asyncio.gather(*(
            client.wait_for_state_peer(
                peer_node.public_key, [State.Connected], [PathType.Direct]
            )
            for client, peer_node in product(env.clients, env.nodes)
            if not client.is_node(peer_node)
        ))

        # Capturing the traffic can be done on nodes or gateways
        # On gateways there's a guarantee that the traffic has arrived
        # however we can't decrypt it easily.
        # On nodes there's no guarantee the packet left the network adapter
        # but we can inspect the packet before it hit the TUN device.
        # Here we capture on both
        gateways = [DOCKER_GW_MAP[param.connection_tag] for param in setup_params]
        gateway_container_names = [container_id(conn_tag) for conn_tag in gateways]
        conns = [client.get_connection() for client in env.clients]
        node_container_names = [
            conn.container_name()
            for conn in conns
            if isinstance(conn, DockerConnection)
        ]

        container_names = gateway_container_names + node_container_names
        # TODO: assert these are docker connections
        print("Will capture batching on containers: ", container_names)
        cnodes = zip(env.clients, env.nodes)

        # the plan is to misalign the peers for better batcing observation. WIthout misalignment
        # peers will form a meshnet almost immediately, already achieving the desired batching effect.
        for client in env.clients:
            await client.stop_device()

        # TODO: this is possible to refactor and use `start_tcpdump` and `stop_tcpdump`
        pcap_capture_tasks = []
        for name in container_names:
            task = asyncio.create_task(
                capture_traffic(
                    name,
                    capture_duration,
                )
            )
            pcap_capture_tasks.append(task)

        # misalign the peers by sleeping some before starting each node again
        for client, node in cnodes:
            await asyncio.sleep(misalign_sleep_amount)
            await client.simple_start()
            await client.set_meshmap(env.api.get_meshmap(node.id))

        await asyncio.gather(*(
            client.wait_for_state_peer(
                peer_node.public_key, [State.Connected], [PathType.Direct]
            )
            for client, peer_node in product(env.clients, env.nodes)
            if not client.is_node(peer_node)
        ))

        pcap_paths = await asyncio.gather(*pcap_capture_tasks)

        filters = [
            None,
            ("icmpv6echorequest", lambda p: p.haslayer(ICMPv6EchoRequest)),
            (
                "ipv46 udp",
                lambda p: (
                    (p.haslayer(IP) or p.haslayer(IPv6)) if p.haslayer(UDP) else True
                ),
            ),
        ]

        for container, pcap_path in zip(container_names, pcap_paths):
            for filt in filters:
                filter_name = filt[0] if filt else "none"
                hs = generate_histogram_from_pcap(
                    pcap_path, capture_duration, filt[1] if filt else None
                )
                title = f"{container}-filter({filter_name})"
                save_histogram(title, hs, "logs", max_height=12)

        for p in pcap_paths:
            os.unlink(p)
