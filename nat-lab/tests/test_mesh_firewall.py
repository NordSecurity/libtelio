from utils import Ping, stun
from utils.asyncio_util import run_async_context
from contextlib import AsyncExitStack
from mesh_api import API
import aiodocker
import asyncio
import config
import pytest
import telio
import utils.container_util as container_util
import utils.testing as testing
from utils import ConnectionTag, new_connection_by_tag, OutputNotifier


@pytest.mark.asyncio
async def test_mesh_firewall_successful_passthrough() -> None:
    async with AsyncExitStack() as exit_stack:
        docker = await exit_stack.enter_async_context(aiodocker.Docker())

        api = API()

        alpha = api.register(
            name="alpha",
            id="96ddb926-4b86-11ec-81d3-0242ac130003",
            private_key="JcnzdKlaRd56T/EnHkbVpNCvYo64YLDpRZsJq14ZU1A=",
            public_key="eES5D8OiQyMXf/pG0ibJSD2QhSnKLW0+6jW7mvtfL0g=",
        )

        beta = api.register(
            name="beta",
            id="7b4548ca-fe5a-4597-8513-896f38c6d6ae",
            private_key="+KqbDiS4KkWlB1iI9DfAnQTX7+c4YvFQzlLQWljbVHc=",
            public_key="5eURKcx0OlMyz2kXOibfHklUwF9pgplc0eBdlo4B3gk=",
        )

        api.assign_ip(alpha.id, "100.74.98.51")
        api.assign_ip(beta.id, "100.74.98.52")

        alpha.set_peer_firewall_settings(beta.id, allow_incoming_connections=True)

        beta.set_peer_firewall_settings(alpha.id, allow_incoming_connections=False)

        connection_alpha = await container_util.get(docker, "nat-lab-cone-client-01-1")
        connection_beta = await container_util.get(docker, "nat-lab-cone-client-02-1")

        client_alpha = await exit_stack.enter_async_context(
            telio.run_meshnet(
                connection_alpha,
                alpha,
                api.get_meshmap(alpha.id),
            )
        )

        client_beta = await exit_stack.enter_async_context(
            telio.run_meshnet(
                connection_beta,
                beta,
                api.get_meshmap(beta.id),
            )
        )

        await testing.wait_long(client_alpha.handshake(beta.public_key))
        await testing.wait_long(client_beta.handshake(alpha.public_key))

        async with Ping(connection_alpha, "100.74.98.52") as ping:
            with pytest.raises(asyncio.TimeoutError):
                await testing.wait_long(ping.wait_for_next_ping())

        async with Ping(connection_beta, "100.74.98.51") as ping:
            await testing.wait_long(ping.wait_for_next_ping())

        # this should still block
        async with Ping(connection_alpha, "100.74.98.52") as ping:
            with pytest.raises(asyncio.TimeoutError):
                await testing.wait_long(ping.wait_for_next_ping())


@pytest.mark.asyncio
async def test_mesh_firewall_reject_packet() -> None:
    async with AsyncExitStack() as exit_stack:
        docker = await exit_stack.enter_async_context(aiodocker.Docker())

        api = API()

        alpha = api.register(
            name="alpha",
            id="96ddb926-4b86-11ec-81d3-0242ac130003",
            private_key="JcnzdKlaRd56T/EnHkbVpNCvYo64YLDpRZsJq14ZU1A=",
            public_key="eES5D8OiQyMXf/pG0ibJSD2QhSnKLW0+6jW7mvtfL0g=",
        )

        beta = api.register(
            name="beta",
            id="7b4548ca-fe5a-4597-8513-896f38c6d6ae",
            private_key="+KqbDiS4KkWlB1iI9DfAnQTX7+c4YvFQzlLQWljbVHc=",
            public_key="5eURKcx0OlMyz2kXOibfHklUwF9pgplc0eBdlo4B3gk=",
        )

        api.assign_ip(alpha.id, "100.74.98.41")
        api.assign_ip(beta.id, "100.74.98.42")

        alpha.set_peer_firewall_settings(beta.id, allow_incoming_connections=False)
        beta.set_peer_firewall_settings(alpha.id, allow_incoming_connections=False)

        connection_alpha = await container_util.get(docker, "nat-lab-cone-client-01-1")
        connection_beta = await container_util.get(docker, "nat-lab-cone-client-02-1")

        client_alpha = await exit_stack.enter_async_context(
            telio.run_meshnet(
                connection_alpha,
                alpha,
                api.get_meshmap(alpha.id),
            )
        )

        client_beta = await exit_stack.enter_async_context(
            telio.run_meshnet(
                connection_beta,
                beta,
                api.get_meshmap(beta.id),
            )
        )

        await testing.wait_long(client_alpha.handshake(beta.public_key))
        await testing.wait_long(client_beta.handshake(alpha.public_key))

        async with Ping(connection_alpha, "100.74.98.42") as ping:
            with pytest.raises(asyncio.TimeoutError):
                await testing.wait_long(ping.wait_for_next_ping())


@pytest.mark.asyncio
async def test_blocking_incoming_connections_from_exit_node() -> None:
    # This tests recreates LLT-3449
    async with AsyncExitStack() as exit_stack:
        docker = await exit_stack.enter_async_context(aiodocker.Docker())

        api = API()

        alpha = api.register(
            name="alpha",
            id="96ddb926-4b86-11ec-81d3-0242ac130003",
            private_key="JcnzdKlaRd56T/EnHkbVpNCvYo64YLDpRZsJq14ZU1A=",
            public_key="eES5D8OiQyMXf/pG0ibJSD2QhSnKLW0+6jW7mvtfL0g=",
        )

        exit_node = api.register(
            name="exit_node",
            id="7b4548ca-fe5a-4597-8513-896f38c6d6ae",
            private_key="+KqbDiS4KkWlB1iI9DfAnQTX7+c4YvFQzlLQWljbVHc=",
            public_key="5eURKcx0OlMyz2kXOibfHklUwF9pgplc0eBdlo4B3gk=",
        )

        api.assign_ip(alpha.id, "100.74.98.41")
        api.assign_ip(exit_node.id, "100.74.98.42")

        alpha.set_peer_firewall_settings(exit_node.id, allow_incoming_connections=True)
        exit_node.set_peer_firewall_settings(alpha.id, allow_incoming_connections=True)

        connection_alpha = await container_util.get(docker, "nat-lab-cone-client-01-1")
        connection_exit_node = await container_util.get(
            docker, "nat-lab-cone-client-02-1"
        )

        client_alpha = await exit_stack.enter_async_context(
            telio.run_meshnet(
                connection_alpha,
                alpha,
                api.get_meshmap(alpha.id),
                telio.AdapterType.BoringTun,
            )
        )

        client_exit_node = await exit_stack.enter_async_context(
            telio.run_meshnet(
                connection_exit_node,
                exit_node,
                api.get_meshmap(exit_node.id),
                telio.AdapterType.BoringTun,
            )
        )

        await testing.wait_long(client_alpha.handshake(exit_node.public_key))
        await testing.wait_long(client_exit_node.handshake(alpha.public_key))

        async def ping_should_work_both_ways():
            async with Ping(connection_alpha, "100.74.98.42") as ping:
                await testing.wait_long(ping.wait_for_next_ping())

            async with Ping(connection_exit_node, "100.74.98.41") as ping:
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

        async with Ping(connection_alpha, "100.74.98.42") as ping:
            with pytest.raises(asyncio.TimeoutError):
                await testing.wait_long(ping.wait_for_next_ping())

        async with Ping(connection_exit_node, "100.74.98.41") as ping:
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
        assert ip_alpha == ip_exit_node

        # Ping should still work

        await ping_should_work_both_ways()

        # Block traffic from exit node

        alpha.set_peer_firewall_settings(exit_node.id, allow_incoming_connections=False)
        await client_alpha.set_meshmap(api.get_meshmap(alpha.id))

        # Ping should only work in one direction

        async with Ping(connection_alpha, "100.74.98.42") as ping:
            await testing.wait_long(ping.wait_for_next_ping())

        async with Ping(connection_exit_node, "100.74.98.41") as ping:
            with pytest.raises(asyncio.TimeoutError):
                await testing.wait_long(ping.wait_for_next_ping())

        # Check that connecting to external services still works

        (ip_alpha, ip_exit_node) = await get_external_ips()
        assert ip_alpha == ip_exit_node


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
        CLIENT_ALPHA_IP = "100.74.98.51"
        CLIENT_BETA_IP = "100.74.98.52"
        PORT = port

        api = API()

        alpha = api.register(
            name="alpha",
            id="96ddb926-4b86-11ec-81d3-0242ac130003",
            private_key="JcnzdKlaRd56T/EnHkbVpNCvYo64YLDpRZsJq14ZU1A=",
            public_key="eES5D8OiQyMXf/pG0ibJSD2QhSnKLW0+6jW7mvtfL0g=",
        )

        beta = api.register(
            name="beta",
            id="7b4548ca-fe5a-4597-8513-896f38c6d6ae",
            private_key="+KqbDiS4KkWlB1iI9DfAnQTX7+c4YvFQzlLQWljbVHc=",
            public_key="5eURKcx0OlMyz2kXOibfHklUwF9pgplc0eBdlo4B3gk=",
        )

        api.assign_ip(alpha.id, CLIENT_ALPHA_IP)
        api.assign_ip(beta.id, CLIENT_BETA_IP)

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

        connection_alpha = await exit_stack.enter_async_context(
            new_connection_by_tag(ConnectionTag.DOCKER_CONE_CLIENT_1)
        )
        connection_beta = await exit_stack.enter_async_context(
            new_connection_by_tag(ConnectionTag.DOCKER_CONE_CLIENT_2)
        )

        client_alpha = await exit_stack.enter_async_context(
            telio.run_meshnet(
                connection_alpha,
                alpha,
                api.get_meshmap(alpha.id),
            )
        )

        client_beta = await exit_stack.enter_async_context(
            telio.run_meshnet(
                connection_beta,
                beta,
                api.get_meshmap(beta.id),
            )
        )

        await testing.wait_long(client_alpha.handshake(beta.public_key))
        await testing.wait_long(client_beta.handshake(alpha.public_key))

        async with Ping(connection_alpha, CLIENT_BETA_IP) as ping:
            if allow_incoming_connections:
                await testing.wait_long(ping.wait_for_next_ping())
            else:
                with pytest.raises(asyncio.TimeoutError):
                    await testing.wait_long(ping.wait_for_next_ping())

        async with Ping(connection_beta, CLIENT_ALPHA_IP) as ping:
            if allow_incoming_connections:
                await testing.wait_long(ping.wait_for_next_ping())
            else:
                with pytest.raises(asyncio.TimeoutError):
                    await testing.wait_long(ping.wait_for_next_ping())

        output_notifier = OutputNotifier()

        async def on_stdout(stdout: str) -> None:
            for line in stdout.splitlines():
                output_notifier.handle_output(line)

        listening_process = connection_alpha.create_process(
            [
                "nc",
                "-nluvv",
                "-p",
                str(PORT),
                "-s",
                CLIENT_ALPHA_IP,
                CLIENT_BETA_IP,
            ]
        )
        send_process = connection_beta.create_process(
            [
                "nc",
                "-nuvvz",
                "-s",
                CLIENT_BETA_IP,
                CLIENT_ALPHA_IP,
                str(PORT),
            ]
        )

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
            run_async_context(
                listening_process.execute(
                    stdout_callback=on_stdout, stderr_callback=on_stdout
                )
            )
        )

        # wait for listening to start
        await testing.wait_long(listening_start_event.wait())

        # registering on_stdout callback on both streams, cuz most of the stdout goes to stderr somehow
        await exit_stack.enter_async_context(
            run_async_context(
                send_process.execute(
                    stdout_callback=on_stdout, stderr_callback=on_stdout
                )
            )
        )

        # wait for sender to start
        await testing.wait_lengthy(sender_start_event.wait())

        # check for connection status according to parameter provided
        if successful:
            await testing.wait_long(connected_event.wait())
        else:
            with pytest.raises(asyncio.TimeoutError):
                await testing.wait_long(connected_event.wait())
