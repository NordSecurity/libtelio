# pylint: disable=too-many-lines

import asyncio
import config
import pytest
import telio
from contextlib import AsyncExitStack
from mesh_api import API
from utils import testing, stun
from utils.connection_tracker import ConnectionLimits
from utils.connection_util import (
    generate_connection_tracker_config,
    ConnectionTag,
    new_connection_with_conn_tracker,
)
from utils.output_notifier import OutputNotifier
from utils.ping import Ping
from utils.router import IPProto, IPStack


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
        api = API()

        (alpha, beta) = api.default_config_two_nodes(
            alpha_ip_stack=alpha_ip_stack, beta_ip_stack=beta_ip_stack
        )
        beta.set_peer_firewall_settings(alpha.id, allow_incoming_connections=False)

        (connection_alpha, alpha_conn_tracker) = await exit_stack.enter_async_context(
            new_connection_with_conn_tracker(
                ConnectionTag.DOCKER_CONE_CLIENT_1,
                generate_connection_tracker_config(
                    ConnectionTag.DOCKER_CONE_CLIENT_1,
                    derp_1_limits=ConnectionLimits(1, 1),
                ),
            )
        )
        (connection_beta, beta_conn_tracker) = await exit_stack.enter_async_context(
            new_connection_with_conn_tracker(
                ConnectionTag.DOCKER_CONE_CLIENT_2,
                generate_connection_tracker_config(
                    ConnectionTag.DOCKER_CONE_CLIENT_2,
                    derp_1_limits=ConnectionLimits(1, 1),
                ),
            )
        )

        client_alpha = await exit_stack.enter_async_context(
            telio.Client(connection_alpha, alpha).run_meshnet(api.get_meshmap(alpha.id))
        )

        client_beta = await exit_stack.enter_async_context(
            telio.Client(connection_beta, beta).run_meshnet(api.get_meshmap(beta.id))
        )

        await testing.wait_long(
            asyncio.gather(
                client_alpha.wait_for_state_on_any_derp([telio.State.Connected]),
                client_beta.wait_for_state_on_any_derp([telio.State.Connected]),
                alpha_conn_tracker.wait_for_event("derp_1"),
                beta_conn_tracker.wait_for_event("derp_1"),
            )
        )
        await testing.wait_lengthy(
            asyncio.gather(
                client_alpha.wait_for_state_peer(
                    beta.public_key, [telio.State.Connected]
                ),
                client_beta.wait_for_state_peer(
                    alpha.public_key, [telio.State.Connected]
                ),
            )
        )

        if alpha_ip_stack in [IPStack.IPv4, IPStack.IPv4v6] and beta_ip_stack in [
            IPStack.IPv4,
            IPStack.IPv4v6,
        ]:
            async with Ping(
                connection_alpha,
                testing.unpack_optional(beta.get_ip_address(IPProto.IPv4)),
                IPProto.IPv4,
            ).run() as ping:
                with pytest.raises(asyncio.TimeoutError):
                    await testing.wait_long(ping.wait_for_next_ping())

            async with Ping(
                connection_beta,
                testing.unpack_optional(alpha.get_ip_address(IPProto.IPv4)),
                IPProto.IPv4,
            ).run() as ping:
                await testing.wait_long(ping.wait_for_next_ping())

            # this should still block
            async with Ping(
                connection_alpha,
                testing.unpack_optional(beta.get_ip_address(IPProto.IPv4)),
                IPProto.IPv4,
            ).run() as ping:
                with pytest.raises(asyncio.TimeoutError):
                    await testing.wait_long(ping.wait_for_next_ping())

        if alpha_ip_stack in [IPStack.IPv6, IPStack.IPv4v6] and beta_ip_stack in [
            IPStack.IPv6,
            IPStack.IPv4v6,
        ]:
            async with Ping(
                connection_alpha,
                testing.unpack_optional(beta.get_ip_address(IPProto.IPv6)),
                IPProto.IPv6,
            ).run() as ping6:
                with pytest.raises(asyncio.TimeoutError):
                    await testing.wait_long(ping6.wait_for_next_ping())

            async with Ping(
                connection_beta,
                testing.unpack_optional(alpha.get_ip_address(IPProto.IPv6)),
                IPProto.IPv6,
            ).run() as ping6:
                await testing.wait_long(ping6.wait_for_next_ping())

            # this should still block
            async with Ping(
                connection_alpha,
                testing.unpack_optional(beta.get_ip_address(IPProto.IPv6)),
                IPProto.IPv6,
            ).run() as ping6:
                with pytest.raises(asyncio.TimeoutError):
                    await testing.wait_long(ping6.wait_for_next_ping())

        assert alpha_conn_tracker.get_out_of_limits() is None
        assert beta_conn_tracker.get_out_of_limits() is None


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
        api = API()

        (alpha, beta) = api.default_config_two_nodes(
            alpha_ip_stack=alpha_ip_stack, beta_ip_stack=beta_ip_stack
        )
        alpha.set_peer_firewall_settings(beta.id, allow_incoming_connections=False)
        beta.set_peer_firewall_settings(alpha.id, allow_incoming_connections=False)

        (connection_alpha, alpha_conn_tracker) = await exit_stack.enter_async_context(
            new_connection_with_conn_tracker(
                ConnectionTag.DOCKER_CONE_CLIENT_1,
                generate_connection_tracker_config(
                    ConnectionTag.DOCKER_CONE_CLIENT_1,
                    derp_1_limits=ConnectionLimits(1, 1),
                ),
            )
        )
        (connection_beta, beta_conn_tracker) = await exit_stack.enter_async_context(
            new_connection_with_conn_tracker(
                ConnectionTag.DOCKER_CONE_CLIENT_2,
                generate_connection_tracker_config(
                    ConnectionTag.DOCKER_CONE_CLIENT_2,
                    derp_1_limits=ConnectionLimits(1, 1),
                ),
            )
        )

        client_alpha = await exit_stack.enter_async_context(
            telio.Client(connection_alpha, alpha).run_meshnet(api.get_meshmap(alpha.id))
        )

        client_beta = await exit_stack.enter_async_context(
            telio.Client(connection_beta, beta).run_meshnet(api.get_meshmap(beta.id))
        )

        await testing.wait_long(
            asyncio.gather(
                client_alpha.wait_for_state_on_any_derp([telio.State.Connected]),
                client_beta.wait_for_state_on_any_derp([telio.State.Connected]),
                alpha_conn_tracker.wait_for_event("derp_1"),
                beta_conn_tracker.wait_for_event("derp_1"),
            )
        )
        await testing.wait_lengthy(
            asyncio.gather(
                client_alpha.wait_for_state_peer(
                    beta.public_key, [telio.State.Connected]
                ),
                client_beta.wait_for_state_peer(
                    alpha.public_key, [telio.State.Connected]
                ),
            )
        )

        if alpha_ip_stack in [IPStack.IPv4, IPStack.IPv4v6] and beta_ip_stack in [
            IPStack.IPv4,
            IPStack.IPv4v6,
        ]:
            async with Ping(
                connection_alpha,
                testing.unpack_optional(beta.get_ip_address(IPProto.IPv4)),
                IPProto.IPv4,
            ).run() as ping:
                with pytest.raises(asyncio.TimeoutError):
                    await testing.wait_long(ping.wait_for_next_ping())

            async with Ping(
                connection_beta,
                testing.unpack_optional(alpha.get_ip_address(IPProto.IPv4)),
                IPProto.IPv4,
            ).run() as ping:
                with pytest.raises(asyncio.TimeoutError):
                    await testing.wait_long(ping.wait_for_next_ping())

        if alpha_ip_stack in [IPStack.IPv6, IPStack.IPv4v6] and beta_ip_stack in [
            IPStack.IPv6,
            IPStack.IPv4v6,
        ]:
            async with Ping(
                connection_alpha,
                testing.unpack_optional(beta.get_ip_address(IPProto.IPv6)),
                IPProto.IPv6,
            ).run() as ping6:
                with pytest.raises(asyncio.TimeoutError):
                    await testing.wait_long(ping6.wait_for_next_ping())

            async with Ping(
                connection_beta,
                testing.unpack_optional(alpha.get_ip_address(IPProto.IPv6)),
                IPProto.IPv6,
            ).run() as ping6:
                with pytest.raises(asyncio.TimeoutError):
                    await testing.wait_long(ping6.wait_for_next_ping())

        assert alpha_conn_tracker.get_out_of_limits() is None
        assert beta_conn_tracker.get_out_of_limits() is None


# This test uses 'stun' and our stun client does not IPv6
@pytest.mark.asyncio
async def test_blocking_incoming_connections_from_exit_node() -> None:
    # This tests recreates LLT-3449
    async with AsyncExitStack() as exit_stack:
        api = API()

        (alpha, exit_node) = api.default_config_two_nodes()
        (connection_alpha, alpha_conn_tracker) = await exit_stack.enter_async_context(
            new_connection_with_conn_tracker(
                ConnectionTag.DOCKER_CONE_CLIENT_1,
                generate_connection_tracker_config(
                    ConnectionTag.DOCKER_CONE_CLIENT_1,
                    derp_1_limits=ConnectionLimits(1, 1),
                    stun_limits=ConnectionLimits(1, 1),
                ),
            )
        )
        (
            connection_exit_node,
            exit_node_conn_tracker,
        ) = await exit_stack.enter_async_context(
            new_connection_with_conn_tracker(
                ConnectionTag.DOCKER_CONE_CLIENT_2,
                generate_connection_tracker_config(
                    ConnectionTag.DOCKER_CONE_CLIENT_2,
                    derp_1_limits=ConnectionLimits(1, 1),
                    stun_limits=ConnectionLimits(1, 5),
                ),
            )
        )

        client_alpha = await exit_stack.enter_async_context(
            telio.Client(
                connection_alpha, alpha, telio.AdapterType.BoringTun
            ).run_meshnet(api.get_meshmap(alpha.id))
        )

        client_exit_node = await exit_stack.enter_async_context(
            telio.Client(
                connection_exit_node, exit_node, telio.AdapterType.BoringTun
            ).run_meshnet(api.get_meshmap(exit_node.id))
        )

        await testing.wait_long(
            asyncio.gather(
                client_alpha.wait_for_state_on_any_derp([telio.State.Connected]),
                client_exit_node.wait_for_state_on_any_derp([telio.State.Connected]),
                alpha_conn_tracker.wait_for_event("derp_1"),
                exit_node_conn_tracker.wait_for_event("derp_1"),
            )
        )
        await testing.wait_lengthy(
            asyncio.gather(
                client_alpha.wait_for_state_peer(
                    exit_node.public_key, [telio.State.Connected]
                ),
                client_exit_node.wait_for_state_peer(
                    alpha.public_key, [telio.State.Connected]
                ),
            )
        )

        async def ping_should_work_both_ways():
            async with Ping(connection_alpha, exit_node.ip_addresses[0]).run() as ping:
                await testing.wait_long(ping.wait_for_next_ping())

            async with Ping(connection_exit_node, alpha.ip_addresses[0]).run() as ping:
                await testing.wait_long(ping.wait_for_next_ping())

        async def get_external_ips():
            ip_alpha = await testing.wait_long(
                stun.get(connection_alpha, config.STUN_SERVER)
            )
            ip_exit_node = await testing.wait_long(
                stun.get(connection_exit_node, config.STUN_SERVER)
            )
            return (ip_alpha, ip_exit_node)

        await ping_should_work_both_ways()

        # Block traffic both ways

        alpha.set_peer_firewall_settings(exit_node.id, allow_incoming_connections=False)
        await client_alpha.set_meshmap(api.get_meshmap(alpha.id))

        exit_node.set_peer_firewall_settings(alpha.id, allow_incoming_connections=False)
        await client_exit_node.set_meshmap(api.get_meshmap(exit_node.id))

        # Ping should fail both ways

        async with Ping(connection_alpha, exit_node.ip_addresses[0]).run() as ping:
            with pytest.raises(asyncio.TimeoutError):
                await testing.wait_long(ping.wait_for_next_ping())

        async with Ping(connection_exit_node, alpha.ip_addresses[0]).run() as ping:
            with pytest.raises(asyncio.TimeoutError):
                await testing.wait_long(ping.wait_for_next_ping())

        # Allow traffic both ways

        alpha.set_peer_firewall_settings(exit_node.id, allow_incoming_connections=True)
        await client_alpha.set_meshmap(api.get_meshmap(alpha.id))

        exit_node.set_peer_firewall_settings(alpha.id, allow_incoming_connections=True)
        await client_exit_node.set_meshmap(api.get_meshmap(exit_node.id))

        # Ping should again work both ways

        await ping_should_work_both_ways()

        # Both nodes should have unique ips

        (ip_alpha, ip_exit_node) = await get_external_ips()
        await testing.wait_long(
            asyncio.gather(
                alpha_conn_tracker.wait_for_event("stun"),
                exit_node_conn_tracker.wait_for_event("stun"),
            )
        )
        assert ip_alpha != ip_exit_node

        # Start routing traffic via the exit node

        await testing.wait_long(client_exit_node.get_router().create_exit_node_route())

        await testing.wait_long(client_alpha.connect_to_exit_node(exit_node.public_key))

        await testing.wait_long(
            client_alpha.wait_for_state_peer(
                exit_node.public_key, [telio.State.Connected]
            )
        )

        # Both nodes should have the same external ip

        (ip_alpha, ip_exit_node) = await get_external_ips()
        await testing.wait_long(
            asyncio.gather(exit_node_conn_tracker.wait_for_event("stun"))
        )
        assert ip_alpha == ip_exit_node

        # Ping should still work

        await ping_should_work_both_ways()

        # Block traffic from exit node

        alpha.set_peer_firewall_settings(exit_node.id, allow_incoming_connections=False)
        await client_alpha.set_meshmap(api.get_meshmap(alpha.id))

        # Ping should only work in one direction

        async with Ping(connection_alpha, exit_node.ip_addresses[0]).run() as ping:
            await testing.wait_long(ping.wait_for_next_ping())

        async with Ping(connection_exit_node, alpha.ip_addresses[0]).run() as ping:
            with pytest.raises(asyncio.TimeoutError):
                await testing.wait_long(ping.wait_for_next_ping())

        # Check that connecting to external services still works

        (ip_alpha, ip_exit_node) = await get_external_ips()
        await testing.wait_long(
            asyncio.gather(exit_node_conn_tracker.wait_for_event("stun"))
        )
        assert ip_alpha == ip_exit_node
        assert alpha_conn_tracker.get_out_of_limits() is None
        assert exit_node_conn_tracker.get_out_of_limits() is None


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

        api = API()

        (alpha, beta) = api.default_config_two_nodes(
            alpha_ip_stack=alpha_ip_stack, beta_ip_stack=beta_ip_stack
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

        CLIENT_PROTO = IPProto.IPv4
        CLIENT_ALPHA_IP = ""
        CLIENT_BETA_IP = ""

        if alpha_ip_stack in [IPStack.IPv4, IPStack.IPv4v6]:
            CLIENT_ALPHA_IP = testing.unpack_optional(
                alpha.get_ip_address(IPProto.IPv4)
            )
            CLIENT_BETA_IP = testing.unpack_optional(beta.get_ip_address(IPProto.IPv4))
        else:
            CLIENT_PROTO = IPProto.IPv6
            CLIENT_ALPHA_IP = testing.unpack_optional(
                alpha.get_ip_address(IPProto.IPv6)
            )
            CLIENT_BETA_IP = testing.unpack_optional(beta.get_ip_address(IPProto.IPv6))

        (connection_alpha, alpha_conn_tracker) = await exit_stack.enter_async_context(
            new_connection_with_conn_tracker(
                ConnectionTag.DOCKER_CONE_CLIENT_1,
                generate_connection_tracker_config(
                    ConnectionTag.DOCKER_CONE_CLIENT_1,
                    derp_1_limits=ConnectionLimits(1, 1),
                ),
            )
        )
        (connection_beta, beta_conn_tracker) = await exit_stack.enter_async_context(
            new_connection_with_conn_tracker(
                ConnectionTag.DOCKER_CONE_CLIENT_2,
                generate_connection_tracker_config(
                    ConnectionTag.DOCKER_CONE_CLIENT_2,
                    derp_1_limits=ConnectionLimits(1, 1),
                ),
            )
        )

        client_alpha = await exit_stack.enter_async_context(
            telio.Client(connection_alpha, alpha).run_meshnet(api.get_meshmap(alpha.id))
        )

        client_beta = await exit_stack.enter_async_context(
            telio.Client(connection_beta, beta).run_meshnet(api.get_meshmap(beta.id))
        )

        await testing.wait_long(
            asyncio.gather(
                client_alpha.wait_for_state_on_any_derp([telio.State.Connected]),
                client_beta.wait_for_state_on_any_derp([telio.State.Connected]),
                alpha_conn_tracker.wait_for_event("derp_1"),
                beta_conn_tracker.wait_for_event("derp_1"),
            )
        )
        await testing.wait_lengthy(
            asyncio.gather(
                client_alpha.wait_for_state_peer(
                    beta.public_key, [telio.State.Connected]
                ),
                client_beta.wait_for_state_peer(
                    alpha.public_key, [telio.State.Connected]
                ),
            )
        )

        async with Ping(connection_alpha, CLIENT_BETA_IP, CLIENT_PROTO).run() as ping:
            if allow_incoming_connections:
                await testing.wait_long(ping.wait_for_next_ping())
            else:
                with pytest.raises(asyncio.TimeoutError):
                    await testing.wait_long(ping.wait_for_next_ping())

        async with Ping(connection_beta, CLIENT_ALPHA_IP, CLIENT_PROTO).run() as ping:
            if allow_incoming_connections:
                await testing.wait_long(ping.wait_for_next_ping())
            else:
                with pytest.raises(asyncio.TimeoutError):
                    await testing.wait_long(ping.wait_for_next_ping())

        output_notifier = OutputNotifier()

        async def on_stdout(stdout: str) -> None:
            for line in stdout.splitlines():
                output_notifier.handle_output(line)

        listening_start_event = asyncio.Event()
        sender_start_event = asyncio.Event()
        connected_event = asyncio.Event()

        output_notifier.notify_output(
            f"listening on [{CLIENT_ALPHA_IP}] {str(PORT)}", listening_start_event
        )

        output_notifier.notify_output(
            f"[{CLIENT_ALPHA_IP}] {str(PORT)} (?) open", sender_start_event
        )

        output_notifier.notify_output(
            f"connect to [{CLIENT_ALPHA_IP}] from (UNKNOWN) [{CLIENT_BETA_IP}]",
            connected_event,
        )

        # registering on_stdout callback on both streams, cuz most of the stdout goes to stderr somehow
        await exit_stack.enter_async_context(
            connection_alpha.create_process(
                [
                    "nc",
                    "-nluvv",
                    "-4" if CLIENT_PROTO == IPProto.IPv4 else "-6",
                    "-p",
                    str(PORT),
                    "-s",
                    CLIENT_ALPHA_IP,
                    CLIENT_BETA_IP,
                ]
            ).run(stdout_callback=on_stdout, stderr_callback=on_stdout)
        )

        # wait for listening to start
        await testing.wait_long(listening_start_event.wait())

        # registering on_stdout callback on both streams, cuz most of the stdout goes to stderr somehow
        await exit_stack.enter_async_context(
            connection_beta.create_process(
                [
                    "nc",
                    "-nuvvz",
                    "-4" if CLIENT_PROTO == IPProto.IPv4 else "-6",
                    "-s",
                    CLIENT_BETA_IP,
                    CLIENT_ALPHA_IP,
                    str(PORT),
                ]
            ).run(stdout_callback=on_stdout, stderr_callback=on_stdout)
        )

        # wait for sender to start
        await testing.wait_lengthy(sender_start_event.wait())

        # check for connection status according to parameter provided
        if successful:
            await testing.wait_long(connected_event.wait())
        else:
            with pytest.raises(asyncio.TimeoutError):
                await testing.wait_long(connected_event.wait())

        assert alpha_conn_tracker.get_out_of_limits() is None
        assert beta_conn_tracker.get_out_of_limits() is None


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
        (telio.AdapterType.BoringTun, telio.AdapterType.BoringTun),
        (telio.AdapterType.BoringTun, telio.AdapterType.LinuxNativeWg),
        (telio.AdapterType.LinuxNativeWg, telio.AdapterType.LinuxNativeWg),
        (telio.AdapterType.LinuxNativeWg, telio.AdapterType.BoringTun),
    ],
)
async def test_mesh_firewall_tcp_stuck_in_last_ack_state_conn_kill_from_server_side(
    alpha_adapter_type: telio.AdapterType,
    beta_adapter_type: telio.AdapterType,
    alpha_ip_stack: IPStack,
    beta_ip_stack: IPStack,
) -> None:
    async with AsyncExitStack() as exit_stack:
        api = API()
        (alpha, beta) = api.default_config_two_nodes(
            alpha_ip_stack=alpha_ip_stack, beta_ip_stack=beta_ip_stack
        )

        PORT = 12345
        CLIENT_PROTO = IPProto.IPv4
        CLIENT_ALPHA_IP = ""
        CLIENT_BETA_IP = ""

        if alpha_ip_stack in [IPStack.IPv4, IPStack.IPv4v6]:
            CLIENT_ALPHA_IP = testing.unpack_optional(
                alpha.get_ip_address(IPProto.IPv4)
            )
            CLIENT_BETA_IP = testing.unpack_optional(beta.get_ip_address(IPProto.IPv4))
        else:
            CLIENT_PROTO = IPProto.IPv6
            CLIENT_ALPHA_IP = testing.unpack_optional(
                alpha.get_ip_address(IPProto.IPv6)
            )
            CLIENT_BETA_IP = testing.unpack_optional(beta.get_ip_address(IPProto.IPv6))

        beta.set_peer_firewall_settings(alpha.id, allow_incoming_connections=False)

        (connection_alpha, alpha_conn_tracker) = await exit_stack.enter_async_context(
            new_connection_with_conn_tracker(
                ConnectionTag.DOCKER_CONE_CLIENT_1,
                generate_connection_tracker_config(
                    ConnectionTag.DOCKER_CONE_CLIENT_1,
                    derp_1_limits=ConnectionLimits(1, 1),
                ),
            )
        )
        (connection_beta, beta_conn_tracker) = await exit_stack.enter_async_context(
            new_connection_with_conn_tracker(
                ConnectionTag.DOCKER_CONE_CLIENT_2,
                generate_connection_tracker_config(
                    ConnectionTag.DOCKER_CONE_CLIENT_2,
                    derp_1_limits=ConnectionLimits(1, 1),
                ),
            )
        )

        client_alpha = await exit_stack.enter_async_context(
            telio.Client(connection_alpha, alpha, alpha_adapter_type).run_meshnet(
                api.get_meshmap(alpha.id)
            )
        )

        client_beta = await exit_stack.enter_async_context(
            telio.Client(connection_beta, beta, beta_adapter_type).run_meshnet(
                api.get_meshmap(beta.id)
            )
        )

        await testing.wait_long(
            asyncio.gather(
                client_alpha.wait_for_state_on_any_derp([telio.State.Connected]),
                client_beta.wait_for_state_on_any_derp([telio.State.Connected]),
            )
        )

        await testing.wait_long(
            asyncio.gather(
                alpha_conn_tracker.wait_for_event("derp_1"),
                beta_conn_tracker.wait_for_event("derp_1"),
            )
        )

        await testing.wait_long(
            asyncio.gather(
                client_alpha.wait_for_state_peer(
                    beta.public_key, [telio.State.Connected]
                ),
                client_beta.wait_for_state_peer(
                    alpha.public_key, [telio.State.Connected]
                ),
            )
        )

        output_notifier = OutputNotifier()

        async def on_stdout(stdout: str) -> None:
            for line in stdout.splitlines():
                output_notifier.handle_output(line)

        async def conntrack_on_stdout(stdout: str) -> None:
            for line in stdout.splitlines():
                if f"src={CLIENT_BETA_IP} dst={CLIENT_ALPHA_IP}" in line:
                    output_notifier.handle_output(line)

        listening_start_event = asyncio.Event()
        sender_start_event = asyncio.Event()
        connected_event = asyncio.Event()
        last_ack_event = asyncio.Event()
        time_wait_event = asyncio.Event()

        output_notifier.notify_output(
            f"listening on [{CLIENT_ALPHA_IP}] {str(PORT)}", listening_start_event
        )

        output_notifier.notify_output(
            f"[{CLIENT_ALPHA_IP}] {str(PORT)} (?) open", sender_start_event
        )

        output_notifier.notify_output(
            f"connect to [{CLIENT_ALPHA_IP}] from (UNKNOWN) [{CLIENT_BETA_IP}]",
            connected_event,
        )

        output_notifier.notify_output("LAST_ACK", last_ack_event)
        output_notifier.notify_output("TIME_WAIT", time_wait_event)

        async with connection_beta.create_process(["conntrack", "-E"]).run(
            stdout_callback=conntrack_on_stdout
        ) as conntrack_proc:
            await testing.wait_normal(conntrack_proc.wait_stdin_ready())
            # registering on_stdout callback on both streams, cuz most of the stdout goes to stderr somehow
            async with connection_alpha.create_process(
                [
                    "nc",
                    "-nlvv",
                    "-4" if CLIENT_PROTO == IPProto.IPv4 else "-6",
                    "-p",
                    str(PORT),
                    "-s",
                    CLIENT_ALPHA_IP,
                    CLIENT_BETA_IP,
                ]
            ).run(stdout_callback=on_stdout, stderr_callback=on_stdout) as listener:
                await testing.wait_normal(listener.wait_stdin_ready())
                await testing.wait_normal(listening_start_event.wait())
                await exit_stack.enter_async_context(
                    connection_beta.create_process(
                        [
                            "nc",
                            "-nvv",
                            "-4" if CLIENT_PROTO == IPProto.IPv4 else "-6",
                            "-s",
                            CLIENT_BETA_IP,
                            CLIENT_ALPHA_IP,
                            str(PORT),
                        ]
                    ).run(stdout_callback=on_stdout, stderr_callback=on_stdout)
                )
                await testing.wait_normal(sender_start_event.wait())
                await testing.wait_normal(connected_event.wait())

            # kill server and check what is happening in conntrack events
            # if everything is correct -> conntrack should show LAST_ACK -> TIME_WAIT
            # if something goes wrong, it will be stuck at LAST_ACK state
            await testing.wait_long(last_ack_event.wait())
            await testing.wait_long(time_wait_event.wait())

        assert alpha_conn_tracker.get_out_of_limits() is None
        assert beta_conn_tracker.get_out_of_limits() is None


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
        (telio.AdapterType.BoringTun, telio.AdapterType.BoringTun),
        (telio.AdapterType.BoringTun, telio.AdapterType.LinuxNativeWg),
        (telio.AdapterType.LinuxNativeWg, telio.AdapterType.LinuxNativeWg),
        (telio.AdapterType.LinuxNativeWg, telio.AdapterType.BoringTun),
    ],
)
async def test_mesh_firewall_tcp_stuck_in_last_ack_state_conn_kill_from_client_side(
    alpha_adapter_type: telio.AdapterType,
    beta_adapter_type: telio.AdapterType,
    alpha_ip_stack: IPStack,
    beta_ip_stack: IPStack,
) -> None:
    async with AsyncExitStack() as exit_stack:
        api = API()
        (alpha, beta) = api.default_config_two_nodes(
            alpha_ip_stack=alpha_ip_stack, beta_ip_stack=beta_ip_stack
        )

        PORT = 12345
        CLIENT_PROTO = IPProto.IPv4
        CLIENT_ALPHA_IP = ""
        CLIENT_BETA_IP = ""

        if alpha_ip_stack in [IPStack.IPv4, IPStack.IPv4v6]:
            CLIENT_ALPHA_IP = testing.unpack_optional(
                alpha.get_ip_address(IPProto.IPv4)
            )
            CLIENT_BETA_IP = testing.unpack_optional(beta.get_ip_address(IPProto.IPv4))
        else:
            CLIENT_PROTO = IPProto.IPv6
            CLIENT_ALPHA_IP = testing.unpack_optional(
                alpha.get_ip_address(IPProto.IPv6)
            )
            CLIENT_BETA_IP = testing.unpack_optional(beta.get_ip_address(IPProto.IPv6))

        beta.set_peer_firewall_settings(alpha.id, allow_incoming_connections=False)

        (connection_alpha, alpha_conn_tracker) = await exit_stack.enter_async_context(
            new_connection_with_conn_tracker(
                ConnectionTag.DOCKER_CONE_CLIENT_1,
                generate_connection_tracker_config(
                    ConnectionTag.DOCKER_CONE_CLIENT_1,
                    derp_1_limits=ConnectionLimits(1, 1),
                ),
            )
        )
        (connection_beta, beta_conn_tracker) = await exit_stack.enter_async_context(
            new_connection_with_conn_tracker(
                ConnectionTag.DOCKER_CONE_CLIENT_2,
                generate_connection_tracker_config(
                    ConnectionTag.DOCKER_CONE_CLIENT_2,
                    derp_1_limits=ConnectionLimits(1, 1),
                ),
            )
        )

        client_alpha = await exit_stack.enter_async_context(
            telio.Client(connection_alpha, alpha, alpha_adapter_type).run_meshnet(
                api.get_meshmap(alpha.id)
            )
        )

        client_beta = await exit_stack.enter_async_context(
            telio.Client(connection_beta, beta, beta_adapter_type).run_meshnet(
                api.get_meshmap(beta.id)
            )
        )

        await testing.wait_long(
            asyncio.gather(
                client_alpha.wait_for_state_on_any_derp([telio.State.Connected]),
                client_beta.wait_for_state_on_any_derp([telio.State.Connected]),
            )
        )

        await testing.wait_long(
            asyncio.gather(
                alpha_conn_tracker.wait_for_event("derp_1"),
                beta_conn_tracker.wait_for_event("derp_1"),
            )
        )

        await testing.wait_long(
            asyncio.gather(
                client_alpha.wait_for_state_peer(
                    beta.public_key, [telio.State.Connected]
                ),
                client_beta.wait_for_state_peer(
                    alpha.public_key, [telio.State.Connected]
                ),
            )
        )

        output_notifier = OutputNotifier()

        async def on_stdout(stdout: str) -> None:
            for line in stdout.splitlines():
                output_notifier.handle_output(line)

        async def conntrack_on_stdout(stdout: str) -> None:
            for line in stdout.splitlines():
                if f"src={CLIENT_ALPHA_IP} dst={CLIENT_BETA_IP}" in line:
                    output_notifier.handle_output(line)

        listening_start_event = asyncio.Event()
        sender_start_event = asyncio.Event()
        connected_event = asyncio.Event()
        last_ack_event = asyncio.Event()
        time_wait_event = asyncio.Event()

        output_notifier.notify_output(
            f"listening on [{CLIENT_ALPHA_IP}] {str(PORT)}", listening_start_event
        )

        output_notifier.notify_output(
            f"[{CLIENT_ALPHA_IP}] {str(PORT)} (?) open", sender_start_event
        )

        output_notifier.notify_output(
            f"connect to [{CLIENT_ALPHA_IP}] from (UNKNOWN) [{CLIENT_BETA_IP}]",
            connected_event,
        )

        output_notifier.notify_output("LAST_ACK", last_ack_event)
        output_notifier.notify_output("TIME_WAIT", time_wait_event)

        async with connection_beta.create_process(["conntrack", "-E"]).run(
            stdout_callback=conntrack_on_stdout
        ) as conntrack_proc:
            await testing.wait_normal(conntrack_proc.wait_stdin_ready())
            async with connection_alpha.create_process(
                [
                    "nc",
                    "-nlvv",
                    "-4" if CLIENT_PROTO == IPProto.IPv4 else "-6",
                    "-p",
                    str(PORT),
                    "-s",
                    CLIENT_ALPHA_IP,
                    CLIENT_BETA_IP,
                ]
            ).run(stdout_callback=on_stdout, stderr_callback=on_stdout) as listener:
                await testing.wait_normal(listener.wait_stdin_ready())
                await testing.wait_normal(listening_start_event.wait())
                # registering on_stdout callback on both streams, cuz most of the stdout goes to stderr somehow
                async with connection_beta.create_process(
                    [
                        "nc",
                        "-nvv",
                        "-4" if CLIENT_PROTO == IPProto.IPv4 else "-6",
                        "-s",
                        CLIENT_BETA_IP,
                        CLIENT_ALPHA_IP,
                        str(PORT),
                    ]
                ).run(stdout_callback=on_stdout, stderr_callback=on_stdout) as client:
                    await testing.wait_normal(client.wait_stdin_ready())
                    await testing.wait_normal(sender_start_event.wait())
                    await testing.wait_normal(connected_event.wait())

                # kill client and check what is happening in conntrack events
                # if everything is correct -> conntrack should show LAST_ACK -> TIME_WAIT
                # if something goes wrong, it will be stuck at LAST_ACK state
                await testing.wait_long(last_ack_event.wait())
                await testing.wait_long(time_wait_event.wait())

        assert alpha_conn_tracker.get_out_of_limits() is None
        assert beta_conn_tracker.get_out_of_limits() is None
