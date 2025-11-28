import asyncio
import itertools
import json
import pytest
from contextlib import AsyncExitStack, asynccontextmanager
from dataclasses import dataclass, field
from ipaddress import AddressValueError, IPv6Address
from itertools import product, zip_longest
from tests.mesh_api import Node, API
from tests.telio import Client
from tests.utils.bindings import (
    default_features,
    Features,
    Server,
    Config,
    LinkState,
    RelayState,
    NodeState,
    PathType,
    TelioAdapterType,
)
from tests.utils.connection import Connection, ConnectionTag
from tests.utils.connection_tracker import ConnTrackerEventsValidator
from tests.utils.connection_util import (
    ConnectionManager,
    new_connection_manager_by_tag,
    new_connection_raw,
)
from tests.utils.logger import log
from tests.utils.ping import ping
from tests.utils.process import Process
from tests.utils.router import IPStack
from tests.utils.tcpdump import make_tcpdump
from typing import Any, AsyncIterator, List, Tuple, Optional, Union
from uuid import UUID


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
    * adapter_type_override - type of the Wireguard adapter to use instead of the default for the given
                 OS (passing None means no override, which means using the default for the given OS)
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
    connection_tracker_config: Optional[List[ConnTrackerEventsValidator]] = field(
        default=None
    )
    adapter_type_override: Optional[TelioAdapterType] = None
    features: Features = field(default_factory=default_features)
    is_meshnet: bool = field(default=True)
    derp_servers: Optional[List[Server]] = field(default=None)
    fingerprint: str = ""


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

    def print_name_mapping(self):
        for node, connection in zip(self.nodes, self.connections):
            log.info("Node %s is running on %s", node.name, connection.connection.tag)


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

    log.debug("Nodes in API:")
    for node in api.nodes.values():
        log.debug(node)

    return api, nodes


async def setup_connections(
    exit_stack: AsyncExitStack,
    connection_parameters: List[
        Union[
            ConnectionTag,
            Tuple[ConnectionTag, Optional[List[ConnTrackerEventsValidator]]],
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
            TelioAdapterType,
            Features,
            str,
            Optional[Config],
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
            Client(
                connection,
                node,
                adapter_type_override,
                features,
                fingerprint=fingerprint,
            ).run(meshnet_config)
        )
        for connection, node, adapter_type_override, features, fingerprint, meshnet_config in client_parameters
    ])


@asynccontextmanager
async def setup_environment(
    exit_stack: AsyncExitStack,
    instances: List[SetupParameters],
    provided_api: Optional[API] = None,
    prepare_vpn: bool = False,
) -> AsyncIterator[Environment]:
    """Sets up the basic environment based on the given parameters.

    It basically combines functionalities of the few functions:
    * `setup_api` (creates mocked core API (if not provided)),
    * `setup_connections` (sets up the connections to the docker containers) and
    * `setup_clients` (creates clients using the given configuration)
    * `prepare_vpn` - Indicates whether VPN containers are needed for the test.
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
                    adapter_type_override=TelioAdapterType.NEP_TUN,
                ),
                SetupParameters(
                    connection_tag=ConnectionTag.DOCKER_CONE_CLIENT_2
                    adapter_type_override=TelioAdapterType.NEP_TUN,
                ),
            ],
        )
    ```

    For more configuration options see `SetupParameters` reference.

    # Arguments

    * `exit_stack` - contextlib.AsyncExitStack instance to manage the async context managers execution
    * `instances` - list of the parameters for each meshnet node to be created
    * `provided_api` - optional mocked Core API instance, if provided a new one won't be created
    * `prepare_vpn` - Indicates whether VPN containers are needed for the test.

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

    if prepare_vpn:
        connections = [
            await exit_stack.enter_async_context(new_connection_raw(conn_tag))
            for conn_tag in [
                ConnectionTag.VM_LINUX_NLX_1,
                ConnectionTag.DOCKER_VPN_1,
                ConnectionTag.DOCKER_VPN_2,
            ]
        ]
        await exit_stack.enter_async_context(make_tcpdump(connections))
        await api.prepare_all_vpn_servers(connections)

    clients = await setup_clients(
        exit_stack,
        list(
            zip(
                [conn_manager.connection for conn_manager in connection_managers],
                nodes,
                [instance.adapter_type_override for instance in instances],
                [instance.features for instance in instances],
                [instance.fingerprint for instance in instances],
                [
                    (
                        api.get_meshnet_config(nodes[idx].id, instance.derp_servers)
                        if instance.is_meshnet
                        else None
                    )
                    for idx, instance in enumerate(instances)
                ],
            )
        ),
    )

    env = Environment(api, nodes, connection_managers, clients)
    env.print_name_mapping()
    yield env

    for conn_manager in connection_managers:
        if conn_manager.tracker:
            violations = await conn_manager.tracker.find_conntracker_violations()
            assert (
                violations is None
            ), f"conntracker ({conn_manager.connection.tag}) reported out of limits {violations}"


async def setup_mesh_nodes(
    exit_stack: AsyncExitStack,
    instances: List[SetupParameters],
    is_timeout_expected: bool = False,
    provided_api: Optional[API] = None,
    prepare_vpn: bool = False,
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
    * `prepare_vpn` - Indicates whether VPN containers needs to be configured

    # Returns

    A new `Environment` instance with the given configuration
    """

    env = await exit_stack.enter_async_context(
        setup_environment(exit_stack, instances, provided_api, prepare_vpn)
    )

    await asyncio.gather(*[
        client.wait_for_state_on_any_derp([RelayState.CONNECTED])
        for client, instance in zip_longest(env.clients, instances)
        if instance.derp_servers != []
    ])

    connection_future = asyncio.gather(*[
        client.wait_for_state_peer(
            other_node.public_key,
            [NodeState.CONNECTED],
            (
                [PathType.DIRECT]
                if instance.features.direct and other_instance.features.direct
                else [PathType.RELAY]
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

    link_state_future = asyncio.gather(*[
        client.wait_for_link_state(
            other_node.public_key,
            LinkState.UP,
            timeout=90 if is_timeout_expected else None,
        )
        for (client, node, instance), (
            _,
            other_node,
            _,
        ) in product(zip_longest(env.clients, env.nodes, instances), repeat=2)
        if node != other_node and instance.features.link_detection is not None
    ])

    if is_timeout_expected:
        with pytest.raises(asyncio.TimeoutError):
            await asyncio.gather(
                connection_future,
                link_state_future,
            )
    else:
        await asyncio.gather(
            connection_future,
            link_state_future,
        )

    return env


def connectivity_stack(node1_stack: IPStack, node2_stack: IPStack) -> Optional[IPStack]:
    """
    Checks, through which paths (v4, v6 or both) the nodes can communicate with each other.
    """
    if (
        (node1_stack, node2_stack) == (IPStack.IPv4, IPStack.IPv4)
        or (node1_stack, node2_stack) == (IPStack.IPv4, IPStack.IPv4v6)
        or (node1_stack, node2_stack) == (IPStack.IPv4v6, IPStack.IPv4)
    ):
        return IPStack.IPv4
    if (node1_stack, node2_stack) == (IPStack.IPv4, IPStack.IPv6) or (
        node1_stack,
        node2_stack,
    ) == (IPStack.IPv6, IPStack.IPv4):
        return None
    if (
        (node1_stack, node2_stack) == (IPStack.IPv6, IPStack.IPv6)
        or (node1_stack, node2_stack) == (IPStack.IPv6, IPStack.IPv4v6)
        or (node1_stack, node2_stack) == (IPStack.IPv4v6, IPStack.IPv6)
    ):
        return IPStack.IPv6
    if (node1_stack, node2_stack) == (IPStack.IPv4v6, IPStack.IPv4v6):
        return IPStack.IPv4v6

    raise ValueError(f"Unsupported IPStack combination: {node1_stack}, {node2_stack}")


async def ping_between_all_nodes(env: Environment) -> None:
    await asyncio.gather(*[
        ping(conn.connection, node.ip_addresses[0])
        for (client, conn), node in itertools.product(
            zip(env.clients, env.connections), env.nodes
        )
        if not client.is_node(node)
    ])


async def send_https_request(
    connection: Connection,
    endpoint: str,
    method: str,
    ca_cert_path: str,
    data: Optional[Any] = None,
    authorization_header: Optional[str] = None,
    extra_headers: Optional[List[str]] = None,
    expect_response: bool = True,
    basic_auth: Optional[Tuple[str, str]] = None,
):
    if extra_headers is None:
        extra_headers = ["Content-Type: application/json"]

    curl_command = [
        "curl",
        "--cacert",
        ca_cert_path,
        "-X",
        method,
        endpoint,
    ]

    for header in extra_headers:
        curl_command.extend(["-H", header])

    if data:
        curl_command.extend(["-d", data])

    if authorization_header:
        curl_command.extend(["-H", f"Authorization: {authorization_header}"])

    if basic_auth:
        username, password = basic_auth
        curl_command.extend(["-u", f"{username}:{password}"])

    process = await connection.create_process(curl_command, quiet=False).execute()
    response = process.get_stdout()
    if expect_response:
        try:
            response = json.loads(response)
            log.debug("[%s] %s %s: %s", connection.tag.name, method, endpoint, response)
            return response
        except json.JSONDecodeError:
            assert False, f"Expected JSON response but got: {response}"
    return None


def verify_uuid(uuid_to_test, version=4):
    try:
        uuid_obj = UUID(uuid_to_test, version=version)
    except ValueError:
        assert False, "Not a valid UUID"
    assert str(uuid_obj) == uuid_to_test, "Not a valid UUID"


def string_to_compressed_ipv6(ip_str_list: List[str]) -> List[str]:
    """
    Pick ipv6 address from a list and convert them to compressed form

    """

    def compress_ip(ip_str: str) -> str:
        try:
            return IPv6Address(ip_str).compressed
        except AddressValueError:
            return ip_str

    return [compress_ip(ip_str) for ip_str in ip_str_list]


# TODO (LLT-6746): move to router.py
async def wait_for_interface_state(
    connection: Connection, interface: str, expected_state: str
) -> bool:
    """
    Wait for an interface state to become up or down.

    Args:
        connection (Connection):
            An active SSH or Docker connection to the instance.
        interface (str):
            Interface name to check.
        expected_state (str):
            Expected state of the interface - up or down.

    Returns:
        bool
    """
    success = False
    for _ in range(2):
        result = await connection.create_process(
            ["sh", "-c", "ip link show %s | awk '/state/ {print $9}'" % interface]
        ).execute()
        state = result.get_stdout().strip()
        if state == expected_state:
            success = True
            break
        log.debug(
            "Interface %s has state: %s, expected state: %s",
            interface,
            state,
            expected_state,
        )
        await asyncio.sleep(1)
    return success


# TODO (LLT-6746): move to router.py
async def print_network_state(connection: Connection) -> None:
    """
    Print current network state of the provided instance.

    Args:
        connection (Connection):
            An active SSH or Docker connection to the provided instance.
    Returns:
        None
    """
    ip_a_log = await connection.create_process(["ip", "a"]).execute()
    ip_a = ip_a_log.get_stdout().strip()
    log.debug(
        "--- Log of ip a command ---\n %s",
        ip_a,
    )

    ip_r_log = await connection.create_process(["ip", "r"]).execute()
    ip_r = ip_r_log.get_stdout().strip()
    log.debug(
        "--- Log of ip r command ---\n %s",
        ip_r,
    )

    ip_tables_log = await connection.create_process(["iptables", "-L"]).execute()
    ip_tables = ip_tables_log.get_stdout().strip()
    log.debug(
        "--- Log of iptables -L command ---\n %s",
        ip_tables,
    )


async def wait_for_log_line(log_process: Process) -> None:
    """
    Accepts process polling for a log line and wait for a log to appear.

    Args:
        log_process (Process):
            An active SSH or Docker process polling for a log line.

    Returns:
        None
    """
    while True:
        await asyncio.sleep(1)
        log_line = log_process.get_stdout().strip()
        if log_line:
            log.info("Expected log line captured: %s ", log_line)
            return
