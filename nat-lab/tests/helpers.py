import asyncio
import pytest
from contextlib import AsyncExitStack, asynccontextmanager
from dataclasses import dataclass, field
from itertools import product, zip_longest
from mesh_api import Node, Meshmap, API
from telio import Client, AdapterType, State, PathType
from telio_features import TelioFeatures
from typing import AsyncIterator, List, Tuple, Optional, Union, Dict, Any
from utils.connection import Connection
from utils.connection_tracker import ConnectionTrackerConfig
from utils.connection_util import (
    ConnectionManager,
    ConnectionTag,
    new_connection_manager_by_tag,
)
from utils.router import IPStack


@dataclass
class SetupParameters:
    ip_stack: IPStack = field(default=IPStack.IPv4v6)
    is_local: bool = field(default=False)
    connection_tag: ConnectionTag = field(default=ConnectionTag.DOCKER_CONE_CLIENT_1)
    connection_tracker_config: Optional[List[ConnectionTrackerConfig]] = field(
        default=None
    )
    adapter_type: AdapterType = field(default=AdapterType.Default)
    features: TelioFeatures = field(default=TelioFeatures())
    is_meshnet: bool = field(default=True)
    derp_servers: Optional[List[Dict[str, Any]]] = field(default=None)


@dataclass
class Environment:
    api: API
    nodes: List[Node]
    connections: List[ConnectionManager]
    clients: List[Client]


def setup_api(node_params: List[Tuple[bool, IPStack]]) -> Tuple[API, List[Node]]:
    api = API()
    nodes = list(api.config_dynamic_nodes(node_params))
    for node, other_node in product(nodes, repeat=2):
        if node != other_node:
            node.set_peer_firewall_settings(other_node.id, True, True)
    return api, nodes


async def setup_connections(
    exit_stack: AsyncExitStack,
    connection_parameters: List[
        Union[
            ConnectionTag, Tuple[ConnectionTag, Optional[List[ConnectionTrackerConfig]]]
        ]
    ],
) -> List[ConnectionManager]:
    return await asyncio.gather(
        *[
            exit_stack.enter_async_context(new_connection_manager_by_tag(param, None))
            if isinstance(param, ConnectionTag)
            else exit_stack.enter_async_context(new_connection_manager_by_tag(*param))
            for param in connection_parameters
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


@asynccontextmanager
async def setup_environment(
    exit_stack: AsyncExitStack,
    instances: List[SetupParameters],
    provided_api: Optional[API] = None,
) -> AsyncIterator[Environment]:
    api, nodes = (
        (provided_api, list(provided_api.nodes.values()))
        if provided_api
        else setup_api(
            [(instance.is_local, instance.ip_stack) for instance in instances]
        )
    )
    connection_managers = await setup_connections(
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
                [conn_manager.connection for conn_manager in connection_managers],
                nodes,
                [instance.adapter_type for instance in instances],
                [instance.features for instance in instances],
                [
                    (
                        api.get_meshmap(nodes[idx].id, instance.derp_servers)
                        if instance.is_meshnet
                        else None
                    )
                    for idx, instance in enumerate(instances)
                ],
            )
        ),
    )

    try:
        yield Environment(api, nodes, connection_managers, clients)
    finally:
        for conn_manager in connection_managers:
            if conn_manager.tracker:
                limits = conn_manager.tracker.get_out_of_limits()
                assert limits is None, f"conntracker reported out of limits {limits}"


async def setup_mesh_nodes(
    exit_stack: AsyncExitStack,
    instances: List[SetupParameters],
    is_timeout_expected: bool = False,
    provided_api: Optional[API] = None,
) -> Environment:
    env = await exit_stack.enter_async_context(
        setup_environment(exit_stack, instances, provided_api)
    )

    await asyncio.gather(
        *[
            client.wait_for_state_on_any_derp([State.Connected])
            for client, instance in zip_longest(env.clients, instances)
            if instance.derp_servers != []
        ]
    )

    connection_future = asyncio.gather(
        *[
            client.wait_for_state_peer(
                other_node.public_key,
                [State.Connected],
                [PathType.Direct]
                if instance.features.direct and other_instance.features.direct
                else [PathType.Relay],
            )
            for (client, node, instance), (
                _,
                other_node,
                other_instance,
            ) in product(zip_longest(env.clients, env.nodes, instances), repeat=2)
            if node != other_node
            and instance.derp_servers != []
            and other_instance.derp_servers != []
        ]
    )
    if is_timeout_expected:
        with pytest.raises(asyncio.TimeoutError):
            await connection_future
    else:
        await connection_future

    return env
