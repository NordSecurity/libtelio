import asyncio
import pytest
from config import WG_SERVERS
from contextlib import AsyncExitStack, asynccontextmanager
from dataclasses import dataclass, field
from itertools import product, zip_longest
from mesh_api import Node, Meshmap, API, stop_tcpdump
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
    """
    Setup parameters for a single Telio node

    # Attributes

    * ip_stack - the IP stack to be used - IPv4, IPv6 or IPv4v6 (default)
    * is_local - indicates whether the node should be marked as local or not (turned off by default)
    * connection_tag - connection tag of the used Docker container (DOCKER_CONE_CLIENT_1 by default)
    * connection_tracker_config - Configuration of the tracking connections with a different nodes
                                  (None by default, which implies that connection checking is disabled)
    * adapter_type - type of the used Wireguard adapter (the default value is AdapterType.Default, which
                     allows Telio client to select the most feasible adapter for the given OS)
    * features - features used with the created Telio instance (while only `is_test_env` is enabled by
                 default, some of the features (like ipv6 support) might be enabled implicitly by other
                 parts of the config)
    * is_meshnet - indicates whether the node should receive meshnet config or not (True by default)
    * derp_servers - list of the provided Derp servers (if not provided, config.DERP_SERVER is used in
                     the meshnet config)
    """

    ip_stack: IPStack = field(default=IPStack.IPv4v6)
    is_local: bool = field(default=False)
    connection_tag: ConnectionTag = field(default=ConnectionTag.DOCKER_CONE_CLIENT_1)
    connection_tracker_config: Optional[List[ConnectionTrackerConfig]] = field(
        default=None
    )
    adapter_type: AdapterType = field(default=AdapterType.Default)
    features: TelioFeatures = field(
        default_factory=lambda: TelioFeatures(is_test_env=True)
    )
    is_meshnet: bool = field(default=True)
    derp_servers: Optional[List[Dict[str, Any]]] = field(default=None)


@dataclass
class Environment:
    """
    A class encapsulating the vital parts of the Telio test environment

    # Attributes

    * api - Core API mocks to imitate nodes registration, create meshnet configs etc.
    * nodes - Configured meshnet nodes
    * connections - Connections to the docker containers
    * clients - Running Tcli clients
    """

    api: API
    nodes: List[Node]
    connections: List[ConnectionManager]
    clients: List[Client]


def setup_api(node_params: List[Tuple[bool, IPStack]]) -> Tuple[API, List[Node]]:
    """Creates an API object with meshnet nodes according to a list of provided node parameters.

    Usually it is called implicitly by `setup_environment` function, but it might be helpful
    to call it separately when we need to do some extra meshnet config before setting up the clients.
    For example, when we would like to modify a meshnet nickname of one of the nodes:
    ```
    api, (alpha, beta) = setup_api(
        [(False, IPStack.IPv4v6), (False, IPStack.IPv4v6)]
    )

    api.assign_nickname(alpha.id, "some_custom_nickname")

    env = await setup_mesh_nodes(
        ...,
        provided_api=api,
    )
    ```
    As you can see, the created api is passed to the `setup_mesh_nodes` function as `provided_api` parameter,
    so it is used and a new instance of an API object is not created.

    # Arguments

    * `node_params` - list of the configs for the wanted meshnet nodes

    # Returns

    A mocked Core API instance + a list of the meshnet nodes included in the config
    """

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
    """Creates connections to the containers corresponding to a given connection tags.

    Useful for testing scenarios which do not involve running Tcli clients,
    like testing the other parts of the infrastructure like STUN servers or just
    the nat-lab architecture.

    To give an example, let's assume that you want to connect to the Docker container just
    to get its IP seen by the STUN server - you can use `setup_connections` function for that:
    ```
    conn_mngr, *_ = await setup_connections(exit_stack, [ConnectionTag.DOCKER_CONE_CLIENT_1])
    stunned_ip = stun.get(conn_mngr.connection, config.STUN_SERVER)
    ```

    # Arguments

    * `exit_stack` - contextlib.AsyncExitStack instance to manage the async context managers execution
    * `connection_parameters` - list of the connection tags with optional conntracker configs

    # Returns

    A list of the Telio connection managers of the connections corresponding to the provided connection tags
    """

    return await asyncio.gather(*[
        (
            exit_stack.enter_async_context(new_connection_manager_by_tag(param, None))
            if isinstance(param, ConnectionTag)
            else exit_stack.enter_async_context(new_connection_manager_by_tag(*param))
        )
        for param in connection_parameters
    ])


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
    """Creates a list of clients for the given arguments.

    By default it is called by `setup_environment` function and currently there are no usecases
    for calling it separately.

    # Arguments

    * `exit_stack` - contextlib.AsyncExitStack instance to manage the async context managers execution
    * `client_parameters` - list of the parameters for each Telio client to be created

    # Returns

    A list of the Telio clients references corresponding to the provided configs
    """

    return await asyncio.gather(*[
        exit_stack.enter_async_context(
            Client(connection, node, adapter_type, features).run(meshmap)
        )
        for connection, node, adapter_type, features, meshmap in client_parameters
    ])


@asynccontextmanager
async def setup_environment(
    exit_stack: AsyncExitStack,
    instances: List[SetupParameters],
    provided_api: Optional[API] = None,
) -> AsyncIterator[Environment]:
    """Sets up the basic environment based on the given parameters.

    It basically combines functionalities of the few functions:
    * `setup_api` (creates mocked core API (if not provided)),
    * `setup_connections` (sets up the connections to the docker containers) and
    * `setup_clients` (creates clients using the given configuration)
    which results in the fully prepared test configuration.
    It also checks whether the number of connections is correct with the conntrackers.

    Usually called from `setup_meshnet_nodes`, calling it separately is useful in all
    scenarios in which you don't use meshnet connections from the beginning.

    The most frequently used setups are already provided as default `SetupParameters` arguments,
    so the most basic case is quite simplistic:
    ```
    env = await setup_environment(
        exit_stack,
        [SetupParameters()],
    )
    ```

    Most of the setups needs at least two nodes (of course using different Docker containers
    or VMs) and often we need to check whether the different Wireguard adapters behave properly,
    in which case the call would look like:
    ```
        env = await setup_environment(
            exit_stack,
            [
                SetupParameters(
                    connection_tag=ConnectionTag.DOCKER_CONE_CLIENT_1
                    adapter_type=AdapterType.BoringTun,
                ),
                SetupParameters(
                    connection_tag=ConnectionTag.DOCKER_CONE_CLIENT_2
                    adapter_type=AdapterType.BoringTun,
                ),
            ],
        )
    ```

    For more configuration options see `SetupParameters` reference.

    # Arguments

    * `exit_stack` - contextlib.AsyncExitStack instance to manage the async context managers execution
    * `instances` - list of the parameters for each meshnet node to be created
    * `provided_api` - optional mocked Core API instance, if provided a new one won't be created

    # Returns

    A new `Environment` instance with the given configuration
    """

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
        stop_tcpdump([server["container"] for server in WG_SERVERS])


async def setup_mesh_nodes(
    exit_stack: AsyncExitStack,
    instances: List[SetupParameters],
    is_timeout_expected: bool = False,
    provided_api: Optional[API] = None,
) -> Environment:
    """The default way of setting up the test environment.

    Sets up the basic environment like `setup_environment` function and then it also connects
    all of the clients to the Derp server and (if direct connection is supported) ensures that
    the obtained connection is direct.

    Because the overall behavior is quite similar to the `setup_env` function, its examples
    work for this one quite well.

    # Arguments

    * `exit_stack` - contextlib.AsyncExitStack instance to manage the async context managers execution
    * `instances` - list of the parameters for each meshnet node to be created
    * `is_timeout_expected` - indicates whether the nodes connection should timeout
    * `provided_api` - optional mocked Core API instance, if provided a new one won't be created

    # Returns

    A new `Environment` instance with the given configuration
    """

    env = await exit_stack.enter_async_context(
        setup_environment(exit_stack, instances, provided_api)
    )

    await asyncio.gather(*[
        client.wait_for_state_on_any_derp([State.Connected])
        for client, instance in zip_longest(env.clients, instances)
        if instance.derp_servers != []
    ])

    connection_future = asyncio.gather(*[
        client.wait_for_state_peer(
            other_node.public_key,
            [State.Connected],
            (
                [PathType.Direct]
                if instance.features.direct and other_instance.features.direct
                else [PathType.Relay]
            ),
            timeout=90 if is_timeout_expected else None,
        )
        for (client, node, instance), (
            _,
            other_node,
            other_instance,
        ) in product(zip_longest(env.clients, env.nodes, instances), repeat=2)
        if node != other_node
        and instance.derp_servers != []
        and other_instance.derp_servers != []
    ])
    if is_timeout_expected:
        with pytest.raises(asyncio.TimeoutError):
            await connection_future
    else:
        await connection_future

    return env
