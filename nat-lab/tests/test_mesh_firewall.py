# pylint: disable=too-many-lines

import asyncio
import config
import pytest
from contextlib import AsyncExitStack
from helpers import SetupParameters, setup_mesh_nodes, setup_api
from mesh_api import Node
from typing import Tuple, Optional
from utils import testing, stun
from utils.bindings import TelioAdapterType
from utils.connection_tracker import (
    ConnectionLimits,
    ConnectionTrackerConfig,
    FiveTuple,
    TcpState,
    ConnectionTracker,
)
from utils.connection_util import generate_connection_tracker_config, ConnectionTag
from utils.netcat import NetCatServer, NetCatClient
from utils.ping import ping
from utils.router import IPProto, IPStack


def get_ips_and_stack(alpha: Node, beta: Node) -> Tuple[IPProto, str, str]:
    if alpha.ip_stack in [IPStack.IPv4, IPStack.IPv4v6]:
        return (
            IPProto.IPv4,
            testing.unpack_optional(alpha.get_ip_address(IPProto.IPv4)),
            testing.unpack_optional(beta.get_ip_address(IPProto.IPv4)),
        )

    return (
        IPProto.IPv6,
        testing.unpack_optional(alpha.get_ip_address(IPProto.IPv6)),
        testing.unpack_optional(beta.get_ip_address(IPProto.IPv6)),
    )


def _setup_params(
    connection_tag: ConnectionTag,
    adapter_type_override: Optional[TelioAdapterType] = None,
    stun_limits: ConnectionLimits = ConnectionLimits(0, 0),
) -> SetupParameters:
    return SetupParameters(
        connection_tag=connection_tag,
        adapter_type_override=adapter_type_override,
        connection_tracker_config=generate_connection_tracker_config(
            connection_tag,
            derp_1_limits=ConnectionLimits(1, 1),
            stun_limits=stun_limits,
        ),
    )


@pytest.mark.parametrize(
    "alpha_ip_stack,beta_ip_stack",
    [
        pytest.param(
            IPStack.IPv4,
            IPStack.IPv4,
            marks=pytest.mark.ipv4,
        ),
        pytest.param(
            IPStack.IPv6,
            IPStack.IPv6,
            marks=pytest.mark.ipv6,
        ),
        pytest.param(
            IPStack.IPv4v6,
            IPStack.IPv4v6,
            marks=pytest.mark.ipv4v6,
        ),
        pytest.param(
            IPStack.IPv4,
            IPStack.IPv4v6,
            marks=pytest.mark.ipv4v6,
        ),
        pytest.param(
            IPStack.IPv6,
            IPStack.IPv4v6,
            marks=pytest.mark.ipv4v6,
        ),
    ],
)
@pytest.mark.asyncio
async def test_mesh_firewall_successful_passthrough(
    alpha_ip_stack: IPStack, beta_ip_stack: IPStack
) -> None:
    async with AsyncExitStack() as exit_stack:
        api, (alpha, beta) = setup_api(
            [(False, alpha_ip_stack), (False, beta_ip_stack)]
        )
        beta.set_peer_firewall_settings(alpha.id, allow_incoming_connections=False)
        env = await setup_mesh_nodes(
            exit_stack,
            [
                _setup_params(
                    ConnectionTag.DOCKER_CONE_CLIENT_1, TelioAdapterType.BORING_TUN
                ),
                _setup_params(ConnectionTag.DOCKER_CONE_CLIENT_2),
            ],
            provided_api=api,
        )
        connection_alpha, connection_beta = [
            conn.connection for conn in env.connections
        ]

        if alpha_ip_stack in [IPStack.IPv4, IPStack.IPv4v6] and beta_ip_stack in [
            IPStack.IPv4,
            IPStack.IPv4v6,
        ]:

            with pytest.raises(asyncio.TimeoutError):
                await ping(
                    connection_alpha,
                    testing.unpack_optional(beta.get_ip_address(IPProto.IPv4)),
                    15,
                )
            await ping(
                connection_beta,
                testing.unpack_optional(alpha.get_ip_address(IPProto.IPv4)),
            )

            # this should still block
            with pytest.raises(asyncio.TimeoutError):
                await ping(
                    connection_alpha,
                    testing.unpack_optional(beta.get_ip_address(IPProto.IPv4)),
                    15,
                )
        if alpha_ip_stack in [IPStack.IPv6, IPStack.IPv4v6] and beta_ip_stack in [
            IPStack.IPv6,
            IPStack.IPv4v6,
        ]:

            with pytest.raises(asyncio.TimeoutError):
                await ping(
                    connection_alpha,
                    testing.unpack_optional(beta.get_ip_address(IPProto.IPv6)),
                    15,
                )

            await ping(
                connection_beta,
                testing.unpack_optional(alpha.get_ip_address(IPProto.IPv6)),
            )

            # this should still block
            with pytest.raises(asyncio.TimeoutError):
                await ping(
                    connection_alpha,
                    testing.unpack_optional(beta.get_ip_address(IPProto.IPv6)),
                    15,
                )


@pytest.mark.parametrize(
    "alpha_ip_stack,beta_ip_stack",
    [
        pytest.param(
            IPStack.IPv4,
            IPStack.IPv4,
            marks=pytest.mark.ipv4,
        ),
        pytest.param(
            IPStack.IPv6,
            IPStack.IPv6,
            marks=pytest.mark.ipv6,
        ),
        pytest.param(
            IPStack.IPv4v6,
            IPStack.IPv4v6,
            marks=pytest.mark.ipv4v6,
        ),
        pytest.param(
            IPStack.IPv4,
            IPStack.IPv4v6,
            marks=pytest.mark.ipv4v6,
        ),
        pytest.param(
            IPStack.IPv6,
            IPStack.IPv4v6,
            marks=pytest.mark.ipv4v6,
        ),
    ],
)
@pytest.mark.asyncio
async def test_mesh_firewall_reject_packet(
    alpha_ip_stack: IPStack, beta_ip_stack: IPStack
) -> None:
    async with AsyncExitStack() as exit_stack:
        api, (alpha, beta) = setup_api(
            [(False, alpha_ip_stack), (False, beta_ip_stack)]
        )
        beta.set_peer_firewall_settings(alpha.id, allow_incoming_connections=False)
        alpha.set_peer_firewall_settings(beta.id, allow_incoming_connections=False)
        env = await setup_mesh_nodes(
            exit_stack,
            [
                _setup_params(
                    ConnectionTag.DOCKER_CONE_CLIENT_1, TelioAdapterType.BORING_TUN
                ),
                _setup_params(ConnectionTag.DOCKER_CONE_CLIENT_2),
            ],
            provided_api=api,
        )
        connection_alpha, connection_beta = [
            conn.connection for conn in env.connections
        ]

        if alpha_ip_stack in [IPStack.IPv4, IPStack.IPv4v6] and beta_ip_stack in [
            IPStack.IPv4,
            IPStack.IPv4v6,
        ]:

            with pytest.raises(asyncio.TimeoutError):
                await ping(
                    connection_alpha,
                    testing.unpack_optional(beta.get_ip_address(IPProto.IPv4)),
                    15,
                )

            with pytest.raises(asyncio.TimeoutError):
                await ping(
                    connection_beta,
                    testing.unpack_optional(alpha.get_ip_address(IPProto.IPv4)),
                    15,
                )

        if alpha_ip_stack in [IPStack.IPv6, IPStack.IPv4v6] and beta_ip_stack in [
            IPStack.IPv6,
            IPStack.IPv4v6,
        ]:

            with pytest.raises(asyncio.TimeoutError):
                await ping(
                    connection_alpha,
                    testing.unpack_optional(beta.get_ip_address(IPProto.IPv6)),
                    15,
                )

            with pytest.raises(asyncio.TimeoutError):
                await ping(
                    connection_beta,
                    testing.unpack_optional(alpha.get_ip_address(IPProto.IPv6)),
                    15,
                )


# This test uses 'stun' and our stun client does not IPv6
@pytest.mark.asyncio
async def test_blocking_incoming_connections_from_exit_node() -> None:
    # This tests recreates LLT-3449
    async with AsyncExitStack() as exit_stack:
        env = await setup_mesh_nodes(
            exit_stack,
            [
                _setup_params(
                    ConnectionTag.DOCKER_CONE_CLIENT_1,
                    TelioAdapterType.BORING_TUN,
                    stun_limits=ConnectionLimits(1, 1),
                ),
                _setup_params(
                    ConnectionTag.DOCKER_CONE_CLIENT_2,
                    stun_limits=ConnectionLimits(1, 5),
                ),
            ],
        )
        api = env.api
        alpha, exit_node = env.nodes
        connection_alpha, connection_exit_node = [
            conn.connection for conn in env.connections
        ]
        client_alpha, client_exit_node = env.clients

        async def ping_should_work_both_ways():
            await ping(connection_alpha, exit_node.ip_addresses[0])

            await ping(connection_exit_node, alpha.ip_addresses[0])

        async def get_external_ips():
            ip_alpha = await stun.get(connection_alpha, config.STUN_SERVER)
            ip_exit_node = await stun.get(connection_exit_node, config.STUN_SERVER)
            return (ip_alpha, ip_exit_node)

        await ping_should_work_both_ways()

        # Block traffic both ways

        alpha.set_peer_firewall_settings(exit_node.id, allow_incoming_connections=False)
        await client_alpha.set_meshnet_config(api.get_meshnet_config(alpha.id))

        exit_node.set_peer_firewall_settings(alpha.id, allow_incoming_connections=False)
        await client_exit_node.set_meshnet_config(api.get_meshnet_config(exit_node.id))

        # Ping should fail both ways
        with pytest.raises(asyncio.TimeoutError):
            await ping(connection_alpha, exit_node.ip_addresses[0], 15)

        with pytest.raises(asyncio.TimeoutError):
            await ping(connection_exit_node, alpha.ip_addresses[0], 15)

        # Allow traffic both ways

        alpha.set_peer_firewall_settings(exit_node.id, allow_incoming_connections=True)
        await client_alpha.set_meshnet_config(api.get_meshnet_config(alpha.id))

        exit_node.set_peer_firewall_settings(alpha.id, allow_incoming_connections=True)
        await client_exit_node.set_meshnet_config(api.get_meshnet_config(exit_node.id))

        # Ping should again work both ways

        await ping_should_work_both_ways()

        # Both nodes should have unique ips

        (ip_alpha, ip_exit_node) = await get_external_ips()
        assert ip_alpha != ip_exit_node

        # Start routing traffic via the exit node

        await client_exit_node.get_router().create_exit_node_route()

        await client_alpha.connect_to_exit_node(exit_node.public_key)

        # Both nodes should have the same external ip

        (ip_alpha, ip_exit_node) = await get_external_ips()
        assert ip_alpha == ip_exit_node

        # Ping should still work

        await ping_should_work_both_ways()

        # Block traffic from exit node

        alpha.set_peer_firewall_settings(exit_node.id, allow_incoming_connections=False)
        await client_alpha.set_meshnet_config(api.get_meshnet_config(alpha.id))

        # Ping should only work in one direction

        await ping(connection_alpha, exit_node.ip_addresses[0])

        with pytest.raises(asyncio.TimeoutError):
            await ping(connection_exit_node, alpha.ip_addresses[0], 15)

        # Check that connecting to external services still works

        (ip_alpha, ip_exit_node) = await get_external_ips()
        assert ip_alpha == ip_exit_node


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "alpha_ip_stack,beta_ip_stack",
    [
        pytest.param(
            IPStack.IPv4,
            IPStack.IPv4,
            marks=pytest.mark.ipv4,
        ),
        pytest.param(
            IPStack.IPv6,
            IPStack.IPv6,
            marks=pytest.mark.ipv6,
        ),
        pytest.param(
            IPStack.IPv4v6,
            IPStack.IPv4v6,
            marks=pytest.mark.ipv4v6,
        ),
        pytest.param(
            IPStack.IPv4,
            IPStack.IPv4v6,
            marks=pytest.mark.ipv4v6,
        ),
        pytest.param(
            IPStack.IPv6,
            IPStack.IPv4v6,
            marks=pytest.mark.ipv4v6,
        ),
    ],
)
@pytest.mark.parametrize(
    "allow_incoming_connections,allow_peer_send_file,port,successful",
    [
        pytest.param(False, True, config.LIBDROP_PORT, True),
        pytest.param(False, False, config.LIBDROP_PORT, False),
        pytest.param(True, True, config.LIBDROP_PORT, True),
        pytest.param(True, False, config.LIBDROP_PORT, True),
        pytest.param(False, True, 12345, False),
        pytest.param(True, True, 12345, True),
        pytest.param(False, False, 12345, False),
        pytest.param(True, False, 12345, True),
    ],
)
async def test_mesh_firewall_file_share_port(
    allow_incoming_connections: bool,
    allow_peer_send_file: bool,
    port: int,
    successful: bool,
    alpha_ip_stack: IPStack,
    beta_ip_stack: IPStack,
) -> None:
    async with AsyncExitStack() as exit_stack:
        PORT = port

        api, (alpha, beta) = setup_api(
            [(False, alpha_ip_stack), (False, beta_ip_stack)]
        )
        alpha.set_peer_firewall_settings(
            beta.id,
            allow_incoming_connections=allow_incoming_connections,
            allow_peer_send_files=allow_peer_send_file,
        )
        beta.set_peer_firewall_settings(
            alpha.id,
            allow_incoming_connections=allow_incoming_connections,
            allow_peer_send_files=allow_peer_send_file,
        )

        (CLIENT_PROTO, CLIENT_ALPHA_IP, CLIENT_BETA_IP) = get_ips_and_stack(alpha, beta)

        env = await setup_mesh_nodes(
            exit_stack,
            [
                _setup_params(
                    ConnectionTag.DOCKER_CONE_CLIENT_1, TelioAdapterType.BORING_TUN
                ),
                _setup_params(ConnectionTag.DOCKER_CONE_CLIENT_2),
            ],
            provided_api=api,
        )
        connection_alpha, connection_beta = [
            conn.connection for conn in env.connections
        ]

        if allow_incoming_connections:
            await ping(connection_alpha, CLIENT_BETA_IP)
        else:
            with pytest.raises(asyncio.TimeoutError):
                await ping(connection_alpha, CLIENT_BETA_IP, 15)

        if allow_incoming_connections:
            await ping(connection_beta, CLIENT_ALPHA_IP)
        else:
            with pytest.raises(asyncio.TimeoutError):
                await ping(connection_beta, CLIENT_ALPHA_IP, 15)

        async with NetCatServer(
            connection_alpha, PORT, udp=True, ipv6=CLIENT_PROTO == IPProto.IPv6
        ).run() as listener:
            # wait for listening to start
            await listener.listening_started()

            async with NetCatClient(
                connection_beta,
                CLIENT_ALPHA_IP,
                PORT,
                udp=True,
                ipv6=CLIENT_PROTO == IPProto.IPv6,
                port_scan=True,
                source_ip=CLIENT_BETA_IP,
            ).run() as client:
                # wait for client to connect
                await client.connection_succeeded()

                # check for connection status according to parameter provided
                if successful:
                    await listener.connection_received()
                else:
                    with pytest.raises(asyncio.TimeoutError):
                        await asyncio.wait_for(listener.connection_received(), 5)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "alpha_ip_stack,beta_ip_stack",
    [
        pytest.param(
            IPStack.IPv4,
            IPStack.IPv4,
            marks=pytest.mark.ipv4,
        ),
        pytest.param(
            IPStack.IPv6,
            IPStack.IPv6,
            marks=pytest.mark.ipv6,
        ),
        pytest.param(
            IPStack.IPv4v6,
            IPStack.IPv4v6,
            marks=pytest.mark.ipv4v6,
        ),
        pytest.param(
            IPStack.IPv4,
            IPStack.IPv4v6,
            marks=pytest.mark.ipv4v6,
        ),
        pytest.param(
            IPStack.IPv6,
            IPStack.IPv4v6,
            marks=pytest.mark.ipv4v6,
        ),
    ],
)
@pytest.mark.parametrize(
    "alpha_adapter_type, beta_adapter_type",
    [
        (TelioAdapterType.BORING_TUN, TelioAdapterType.BORING_TUN),
        (TelioAdapterType.BORING_TUN, TelioAdapterType.LINUX_NATIVE_TUN),
        (TelioAdapterType.LINUX_NATIVE_TUN, TelioAdapterType.BORING_TUN),
    ],
)
async def test_mesh_firewall_tcp_stuck_in_last_ack_state_conn_kill_from_server_side(
    alpha_adapter_type: Optional[TelioAdapterType],
    beta_adapter_type: Optional[TelioAdapterType],
    alpha_ip_stack: IPStack,
    beta_ip_stack: IPStack,
) -> None:
    async with AsyncExitStack() as exit_stack:
        api, (alpha, beta) = setup_api(
            [(False, alpha_ip_stack), (False, beta_ip_stack)]
        )
        beta.set_peer_firewall_settings(alpha.id, allow_incoming_connections=False)

        PORT = 12345
        (CLIENT_PROTO, CLIENT_ALPHA_IP, CLIENT_BETA_IP) = get_ips_and_stack(alpha, beta)

        env = await setup_mesh_nodes(
            exit_stack,
            [
                _setup_params(ConnectionTag.DOCKER_CONE_CLIENT_1, alpha_adapter_type),
                _setup_params(ConnectionTag.DOCKER_CONE_CLIENT_2, beta_adapter_type),
            ],
            provided_api=api,
        )
        connection_alpha, connection_beta = [
            conn.connection for conn in env.connections
        ]

        last_ack_event = asyncio.Event()
        time_wait_event = asyncio.Event()

        async with ConnectionTracker(
            connection_beta,
            [
                ConnectionTrackerConfig(
                    "nc",
                    ConnectionLimits(),
                    FiveTuple(protocol="tcp", dst_ip=CLIENT_ALPHA_IP, dst_port=PORT),
                )
            ],
            True,
        ).run() as conntrack:
            conntrack.notify_on_tcp_state(TcpState.LAST_ACK, last_ack_event)
            conntrack.notify_on_tcp_state(TcpState.TIME_WAIT, time_wait_event)

            async with NetCatServer(
                connection_alpha, PORT, ipv6=CLIENT_PROTO == IPProto.IPv6
            ).run() as listener:
                await listener.listening_started()

                async with NetCatClient(
                    connection_beta,
                    CLIENT_ALPHA_IP,
                    PORT,
                    ipv6=CLIENT_PROTO == IPProto.IPv6,
                    source_ip=CLIENT_BETA_IP,
                ).run() as client:
                    await asyncio.gather(
                        listener.connection_received(), client.connection_succeeded()
                    )

            # kill server and check what is happening in conntrack events
            # if everything is correct -> conntrack should show LAST_ACK -> TIME_WAIT
            # if something goes wrong, it will be stuck at LAST_ACK state
            await last_ack_event.wait()
            await time_wait_event.wait()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "alpha_ip_stack,beta_ip_stack",
    [
        pytest.param(
            IPStack.IPv4,
            IPStack.IPv4,
            marks=pytest.mark.ipv4,
        ),
        pytest.param(
            IPStack.IPv6,
            IPStack.IPv6,
            marks=pytest.mark.ipv6,
        ),
        pytest.param(
            IPStack.IPv4v6,
            IPStack.IPv4v6,
            marks=pytest.mark.ipv4v6,
        ),
        pytest.param(
            IPStack.IPv4,
            IPStack.IPv4v6,
            marks=pytest.mark.ipv4v6,
        ),
        pytest.param(
            IPStack.IPv6,
            IPStack.IPv4v6,
            marks=pytest.mark.ipv4v6,
        ),
    ],
)
@pytest.mark.parametrize(
    "alpha_adapter_type, beta_adapter_type",
    [
        (TelioAdapterType.BORING_TUN, TelioAdapterType.BORING_TUN),
        (TelioAdapterType.BORING_TUN, TelioAdapterType.LINUX_NATIVE_TUN),
        (TelioAdapterType.LINUX_NATIVE_TUN, TelioAdapterType.BORING_TUN),
    ],
)
async def test_mesh_firewall_tcp_stuck_in_last_ack_state_conn_kill_from_client_side(
    alpha_adapter_type: Optional[TelioAdapterType],
    beta_adapter_type: Optional[TelioAdapterType],
    alpha_ip_stack: IPStack,
    beta_ip_stack: IPStack,
) -> None:
    async with AsyncExitStack() as exit_stack:
        api, (alpha, beta) = setup_api(
            [(False, alpha_ip_stack), (False, beta_ip_stack)]
        )
        beta.set_peer_firewall_settings(alpha.id, allow_incoming_connections=False)

        PORT = 12345
        (CLIENT_PROTO, CLIENT_ALPHA_IP, CLIENT_BETA_IP) = get_ips_and_stack(alpha, beta)

        env = await setup_mesh_nodes(
            exit_stack,
            [
                _setup_params(ConnectionTag.DOCKER_CONE_CLIENT_1, alpha_adapter_type),
                _setup_params(ConnectionTag.DOCKER_CONE_CLIENT_2, beta_adapter_type),
            ],
            provided_api=api,
        )
        connection_alpha, connection_beta = [
            conn.connection for conn in env.connections
        ]

        last_ack_event = asyncio.Event()
        time_wait_event = asyncio.Event()

        async with ConnectionTracker(
            connection_beta,
            [
                ConnectionTrackerConfig(
                    "nc",
                    ConnectionLimits(),
                    FiveTuple(protocol="tcp", dst_ip=CLIENT_ALPHA_IP, dst_port=PORT),
                )
            ],
            True,
        ).run() as conntrack:
            conntrack.notify_on_tcp_state(TcpState.LAST_ACK, last_ack_event)
            conntrack.notify_on_tcp_state(TcpState.TIME_WAIT, time_wait_event)
            async with NetCatServer(
                connection_alpha, PORT, ipv6=CLIENT_PROTO == IPProto.IPv6
            ).run() as listener:
                await listener.listening_started()

                async with NetCatClient(
                    connection_beta,
                    CLIENT_ALPHA_IP,
                    PORT,
                    detached=True,
                    ipv6=CLIENT_PROTO == IPProto.IPv6,
                    source_ip=CLIENT_BETA_IP,
                ).run() as client:
                    await asyncio.gather(
                        listener.connection_received(), client.connection_succeeded()
                    )

                # kill client and check what is happening in conntrack events
                # if everything is correct -> conntrack should show LAST_ACK -> TIME_WAIT
                # if something goes wrong, it will be stuck at LAST_ACK state
                await last_ack_event.wait()
                await time_wait_event.wait()
