import asyncio
from contextlib import AsyncExitStack
from dataclasses import dataclass, field
from itertools import product
from mesh_api import Node, Meshmap, API
from telio import Client, AdapterType
from telio_features import TelioFeatures
from typing import List, Tuple, Optional
from utils.connection import Connection
from utils.connection_tracker import ConnectionTracker, ConnectionTrackerConfig
from utils.connection_util import ConnectionTag, new_connection_manager_by_tag
from utils.network_switcher import NetworkSwitcher


@dataclass
class SetupParameters:
    is_local: bool = field(default=False)
    connection_tag: ConnectionTag = field(default=ConnectionTag.DOCKER_CONE_CLIENT_1)
    connection_tracker_config: Optional[List[ConnectionTrackerConfig]] = field(
        default=None
    )
    adapter_type: AdapterType = field(default=AdapterType.Default)
    features: TelioFeatures = field(default=TelioFeatures())
    is_meshnet: bool = field(default=True)


@dataclass
class Environment:
    api: API
    nodes: List[Node]
    connections: List[
        Tuple[
            Connection,
            Optional[Connection],
            NetworkSwitcher,
            Optional[ConnectionTracker],
        ]
    ]
    clients: List[Client]


def setup_api(node_params: List[bool]) -> Tuple[API, List[Node]]:
    api = API()
    nodes = list(api.config_dynamic_nodes(node_params))
    for node, other_node in product(nodes, repeat=2):
        if node != other_node:
            node.set_peer_firewall_settings(other_node.id, True, True)
    return api, nodes


async def setup_connections(
    exit_stack: AsyncExitStack,
    connection_parameters: List[
        Tuple[ConnectionTag, Optional[List[ConnectionTrackerConfig]]]
    ],
) -> List[
    Tuple[
        Connection, Optional[Connection], NetworkSwitcher, Optional[ConnectionTracker]
    ]
]:
    return await asyncio.gather(
        *[
            exit_stack.enter_async_context(
                new_connection_manager_by_tag(connection_tag, connection_tracker_config)
            )
            for connection_tag, connection_tracker_config in connection_parameters
        ]
    )


async def setup_clients(
    exit_stack: AsyncExitStack,
    client_parameters: List[
        Tuple[
            Connection,
            Node,
            AdapterType,
            TelioFeatures,
            Optional[Meshmap],
        ]
    ],
) -> List[Client]:
    return await asyncio.gather(
        *[
            exit_stack.enter_async_context(
                Client(connection, node, adapter_type, features).run(meshmap)
            )
            for connection, node, adapter_type, features, meshmap in client_parameters
        ]
    )


async def setup_environment(
    exit_stack: AsyncExitStack, instances: List[SetupParameters]
) -> Environment:
    api, nodes = setup_api([instance.is_local for instance in instances])
    connections = await setup_connections(
        exit_stack,
        [
            (
                instance.connection_tag,
                instance.connection_tracker_config,
            )
            for instance in instances
        ],
    )

    clients = await setup_clients(
        exit_stack,
        list(
            zip(
                [conn for conn, _, _, _ in connections],
                nodes,
                [instance.adapter_type for instance in instances],
                [instance.features for instance in instances],
                [
                    (api.get_meshmap(nodes[idx].id) if instance.is_meshnet else None)
                    for idx, instance in enumerate(instances)
                ],
            )
        ),
    )

    return Environment(api, nodes, connections, clients)
