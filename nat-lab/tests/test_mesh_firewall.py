from utils import Ping, stun
from contextlib import AsyncExitStack
from mesh_api import API
import asyncio
import config
import pytest
import telio
import utils.testing as testing
from utils import (
    ConnectionTag,
    new_connection_with_conn_tracker,
    OutputNotifier,
)
from utils.connection_tracker import (
    generate_connection_tracker_config,
    ConnectionLimits,
)


@pytest.mark.asyncio
async def test_mesh_firewall_successful_passthrough() -> None:
    async with AsyncExitStack() as exit_stack:
        api = API()

        (alpha, beta) = api.default_config_two_nodes()
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
            telio.Client(connection_alpha, alpha,).run_meshnet(
                api.get_meshmap(alpha.id),
            )
        )

        client_beta = await exit_stack.enter_async_context(
            telio.Client(connection_beta, beta,).run_meshnet(
                api.get_meshmap(beta.id),
            )
        )

        await testing.wait_long(
            asyncio.gather(
                client_alpha.wait_for_any_derp_state([telio.State.Connected]),
                client_beta.wait_for_any_derp_state([telio.State.Connected]),
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
                client_alpha.handshake(beta.public_key),
                client_beta.handshake(alpha.public_key),
            )
        )

        async with Ping(connection_alpha, beta.ip_addresses[0]).run() as ping:
            with pytest.raises(asyncio.TimeoutError):
                await testing.wait_long(ping.wait_for_next_ping())

        async with Ping(connection_beta, alpha.ip_addresses[0]).run() as ping:
            await testing.wait_long(ping.wait_for_next_ping())

        # this should still block
        async with Ping(connection_alpha, beta.ip_addresses[0]).run() as ping:
            with pytest.raises(asyncio.TimeoutError):
                await testing.wait_long(ping.wait_for_next_ping())

        assert alpha_conn_tracker.get_out_of_limits() is None
        assert beta_conn_tracker.get_out_of_limits() is None


@pytest.mark.asyncio
async def test_mesh_firewall_reject_packet() -> None:
    async with AsyncExitStack() as exit_stack:
        api = API()

        (alpha, beta) = api.default_config_two_nodes()
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
            telio.Client(connection_alpha, alpha,).run_meshnet(
                api.get_meshmap(alpha.id),
            )
        )

        client_beta = await exit_stack.enter_async_context(
            telio.Client(connection_beta, beta,).run_meshnet(
                api.get_meshmap(beta.id),
            )
        )

        await testing.wait_long(
            asyncio.gather(
                client_alpha.wait_for_any_derp_state([telio.State.Connected]),
                client_beta.wait_for_any_derp_state([telio.State.Connected]),
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
                client_alpha.handshake(beta.public_key),
                client_beta.handshake(alpha.public_key),
            )
        )

        async with Ping(connection_alpha, beta.ip_addresses[0]).run() as ping:
            with pytest.raises(asyncio.TimeoutError):
                await testing.wait_long(ping.wait_for_next_ping())

        async with Ping(connection_beta, alpha.ip_addresses[0]).run() as ping:
            with pytest.raises(asyncio.TimeoutError):
                await testing.wait_long(ping.wait_for_next_ping())

        assert alpha_conn_tracker.get_out_of_limits() is None
        assert beta_conn_tracker.get_out_of_limits() is None


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
                connection_alpha,
                alpha,
                telio.AdapterType.BoringTun,
            ).run_meshnet(
                api.get_meshmap(alpha.id),
            )
        )

        client_exit_node = await exit_stack.enter_async_context(
            telio.Client(
                connection_exit_node,
                exit_node,
                telio.AdapterType.BoringTun,
            ).run_meshnet(
                api.get_meshmap(exit_node.id),
            )
        )

        await testing.wait_long(
            asyncio.gather(
                client_alpha.wait_for_any_derp_state([telio.State.Connected]),
                client_exit_node.wait_for_any_derp_state([telio.State.Connected]),
            )
        )

        await testing.wait_long(
            asyncio.gather(
                alpha_conn_tracker.wait_for_event("derp_1"),
                exit_node_conn_tracker.wait_for_event("derp_1"),
            )
        )

        await testing.wait_long(
            asyncio.gather(
                client_alpha.handshake(exit_node.public_key),
                client_exit_node.handshake(alpha.public_key),
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

        await testing.wait_long(
            client_alpha.connect_to_exit_node(
                exit_node.public_key,
            )
        )

        await testing.wait_long(client_alpha.handshake(exit_node.public_key))

        # Both nodes should have the same external ip

        (ip_alpha, ip_exit_node) = await get_external_ips()
        await testing.wait_long(
            asyncio.gather(
                exit_node_conn_tracker.wait_for_event("stun"),
            )
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
            asyncio.gather(
                exit_node_conn_tracker.wait_for_event("stun"),
            )
        )
        assert ip_alpha == ip_exit_node
        assert alpha_conn_tracker.get_out_of_limits() is None
        assert exit_node_conn_tracker.get_out_of_limits() is None


@pytest.mark.asyncio
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
) -> None:
    async with AsyncExitStack() as exit_stack:
        PORT = port

        api = API()

        (alpha, beta) = api.default_config_two_nodes()
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

        CLIENT_ALPHA_IP = alpha.ip_addresses[0]
        CLIENT_BETA_IP = beta.ip_addresses[0]

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
            telio.Client(connection_alpha, alpha,).run_meshnet(
                api.get_meshmap(alpha.id),
            )
        )

        client_beta = await exit_stack.enter_async_context(
            telio.Client(connection_beta, beta,).run_meshnet(
                api.get_meshmap(beta.id),
            )
        )

        await testing.wait_long(
            asyncio.gather(
                client_alpha.wait_for_any_derp_state([telio.State.Connected]),
                client_beta.wait_for_any_derp_state([telio.State.Connected]),
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
                client_alpha.handshake(beta.public_key),
                client_beta.handshake(alpha.public_key),
            )
        )

        async with Ping(connection_alpha, CLIENT_BETA_IP).run() as ping:
            if allow_incoming_connections:
                await testing.wait_long(ping.wait_for_next_ping())
            else:
                with pytest.raises(asyncio.TimeoutError):
                    await testing.wait_long(ping.wait_for_next_ping())

        async with Ping(connection_beta, CLIENT_ALPHA_IP).run() as ping:
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
            f"listening on [{CLIENT_ALPHA_IP}] {str(PORT)}",
            listening_start_event,
        )

        output_notifier.notify_output(
            f"[{CLIENT_ALPHA_IP}] {str(PORT)} (?) open",
            sender_start_event,
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
