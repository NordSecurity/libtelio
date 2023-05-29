from utils import Ping
from config import DERP_PRIMARY, DERP_SECONDARY, DERP_TERTIARY
from contextlib import AsyncExitStack
from mesh_api import API
from utils import ConnectionTag, new_connection_by_tag, testing
from derp_cli import check_derp_connection
import asyncio
import os
import pytest
import telio


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "adapter_type",
    [
        pytest.param(
            telio.AdapterType.BoringTun,
        ),
        pytest.param(
            telio.AdapterType.LinuxNativeWg,
            marks=pytest.mark.linux_native,
        ),
    ],
)
# test client reconnection
async def test_derp_reconnect_2clients(adapter_type: telio.AdapterType) -> None:
    # TODO test tcp keepalive
    async with AsyncExitStack() as exit_stack:
        DERP1_IP = str(DERP_PRIMARY["ipv4"])
        DERP2_IP = str(DERP_SECONDARY["ipv4"])
        CLIENT_ALPHA_IP = "100.72.31.21"
        CLIENT_BETA_IP = "100.72.31.22"

        api = API()
        alpha = api.register(
            name="alpha",
            id="96ddb926-4b86-11ec-81d3-0242ac130003",
            private_key="IGm+42FLMMGZRaQvk6F3UPbl+T/CBk8W+NPoX2/AdlU=",
            public_key="41CCEssnYIh8/8D8YvbTfWEcFanG3D0I0z1tRcN1Lyc=",
        )
        beta = api.register(
            name="beta",
            id="7b4548ca-fe5a-4597-8513-896f38c6d6ae",
            private_key="SPFD84gPtBNc3iGY9Cdrj+mSCwBeh3mCMWfPaeWQolw=",
            public_key="Q1M3VKUcfTmGsrRzY6BpNds1yDIUvPVcs/2TySv/t1U=",
        )
        api.assign_ip(alpha.id, CLIENT_ALPHA_IP)
        api.assign_ip(beta.id, CLIENT_BETA_IP)

        # create a rule in  iptables to accept connections
        beta.set_peer_firewall_settings(alpha.id, allow_incoming_connections=True)

        # ALPHA will use the cone nat : "nat-lab-cone-client-01-1
        alpha_connection = await exit_stack.enter_async_context(
            new_connection_by_tag(ConnectionTag.DOCKER_CONE_CLIENT_1)
        )

        # BETA will use the cone nat : "nat-lab-cone-client-02-1
        beta_connection = await exit_stack.enter_async_context(
            new_connection_by_tag(ConnectionTag.DOCKER_CONE_CLIENT_2)
        )

        alpha_client = await exit_stack.enter_async_context(
            telio.run_meshnet(
                alpha_connection,
                alpha,
                api.get_meshmap(alpha.id),
                adapter_type,
            )
        )

        beta_client = await exit_stack.enter_async_context(
            telio.run_meshnet(
                beta_connection,
                beta,
                api.get_meshmap(beta.id),
            )
        )

        # As the wireguard protocol routing scheme is based on the public key
        # a handshake is needed to let both clients aware of the key of each other
        await testing.wait_long(alpha_client.handshake(beta.public_key))
        await testing.wait_long(beta_client.handshake(alpha.public_key))

        # ==============================================================
        # Initial state (ping test 1):
        #
        # [DERP1]===[DERP2]
        #     /  \___
        #  [GW1]     [GW2]
        #   /           \
        # [ALPHA]     [BETA]

        await testing.wait_lengthy(check_derp_connection(alpha_client, DERP1_IP, True))
        await testing.wait_lengthy(check_derp_connection(beta_client, DERP1_IP, True))

        async with Ping(alpha_connection, CLIENT_BETA_IP) as ping:
            await testing.wait_long(ping.wait_for_next_ping())

        # ==============================================================
        # Break the connection:
        #
        # [DERP1]===[DERP2]
        #     /  X
        #  [GW1]     [GW2]
        #   /           \
        # [ALPHA]     [BETA]

        # an iptables rule is placed in order to reject connections and
        # send a TCP reset to the client BETA
        await exit_stack.enter_async_context(
            beta_client.get_router().break_tcp_conn_to_host(DERP1_IP)
        )

        # Wait till connection is broken
        await testing.wait_lengthy(check_derp_connection(beta_client, DERP1_IP, False))

        # ==============================================================
        # Wait till new connection is established
        # Final state (ping test 2):
        #
        # [DERP1]===[DERP2]
        #     /       \
        #  [GW1]     [GW2]
        #   /           \
        # [ALPHA]     [BETA]

        await testing.wait_lengthy(check_derp_connection(beta_client, DERP2_IP, True))

        # Ping peer to check if connection truly works
        async with Ping(alpha_connection, CLIENT_BETA_IP) as ping:
            await testing.wait_long(ping.wait_for_next_ping())


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "adapter_type",
    [
        pytest.param(
            telio.AdapterType.BoringTun,
        ),
        pytest.param(
            telio.AdapterType.LinuxNativeWg,
            marks=pytest.mark.linux_native,
        ),
    ],
)
# test client reconnection
async def test_derp_reconnect_3clients(adapter_type: telio.AdapterType) -> None:
    # TODO test tcp keepalive
    async with AsyncExitStack() as exit_stack:
        DERP1_IP = str(DERP_PRIMARY["ipv4"])
        DERP2_IP = str(DERP_SECONDARY["ipv4"])
        DERP3_IP = str(DERP_TERTIARY["ipv4"])
        CLIENT_ALPHA_IP = "100.72.32.21"
        CLIENT_BETA_IP = "100.72.32.22"
        CLIENT_GAMMA_IP = "100.72.32.23"

        api = API()
        alpha = api.register(
            name="alpha",
            id="96ddb926-4b86-11ec-81d3-0242ac130003",
            private_key="IGm+42FLMMGZRaQvk6F3UPbl+T/CBk8W+NPoX2/AdlU=",
            public_key="41CCEssnYIh8/8D8YvbTfWEcFanG3D0I0z1tRcN1Lyc=",
        )
        beta = api.register(
            name="beta",
            id="7b4548ca-fe5a-4597-8513-896f38c6d6ae",
            private_key="SPFD84gPtBNc3iGY9Cdrj+mSCwBeh3mCMWfPaeWQolw=",
            public_key="Q1M3VKUcfTmGsrRzY6BpNds1yDIUvPVcs/2TySv/t1U=",
        )
        gamma = api.register(
            name="gamma",
            id="6b825055-91fa-41b7-ac65-78dbf397a2cd",
            private_key="WMsz2uwtYIlqDEfkGjLX7tz1hcK+ylecHvL+z0tAqWM=",
            public_key="sT82kS+0VFH6TPIlLqFzOJ7e4OOc8udFCZt1O9ZUv3k=",
        )
        api.assign_ip(alpha.id, CLIENT_ALPHA_IP)
        api.assign_ip(beta.id, CLIENT_BETA_IP)
        api.assign_ip(gamma.id, CLIENT_GAMMA_IP)

        beta.set_peer_firewall_settings(alpha.id, allow_incoming_connections=True)
        beta.set_peer_firewall_settings(gamma.id, allow_incoming_connections=True)
        gamma.set_peer_firewall_settings(alpha.id, allow_incoming_connections=True)
        gamma.set_peer_firewall_settings(beta.id, allow_incoming_connections=True)

        alpha_connection = await exit_stack.enter_async_context(
            new_connection_by_tag(ConnectionTag.DOCKER_CONE_CLIENT_1)
        )
        beta_connection = await exit_stack.enter_async_context(
            new_connection_by_tag(ConnectionTag.DOCKER_CONE_CLIENT_2)
        )
        gamma_connection = await exit_stack.enter_async_context(
            new_connection_by_tag(ConnectionTag.DOCKER_SYMMETRIC_CLIENT_1)
        )

        alpha_client = await exit_stack.enter_async_context(
            telio.run_meshnet(
                alpha_connection,
                alpha,
                api.get_meshmap(alpha.id),
                adapter_type,
            )
        )
        beta_client = await exit_stack.enter_async_context(
            telio.run_meshnet(
                beta_connection,
                beta,
                api.get_meshmap(beta.id),
            )
        )
        gamma_client = await exit_stack.enter_async_context(
            telio.run_meshnet(
                gamma_connection,
                gamma,
                api.get_meshmap(gamma.id),
            )
        )

        await testing.wait_lengthy(alpha_client.handshake(beta.public_key))
        await testing.wait_lengthy(alpha_client.handshake(gamma.public_key))
        await testing.wait_lengthy(beta_client.handshake(alpha.public_key))
        await testing.wait_lengthy(beta_client.handshake(gamma.public_key))
        await testing.wait_lengthy(gamma_client.handshake(alpha.public_key))
        await testing.wait_lengthy(gamma_client.handshake(beta.public_key))

        # ==============================================================
        # Initial state (ping test 1):
        #    ╔═════════╦═══════════╗
        # [DERP1]   [DERP2]     [DERP3]
        #    |\ \_____________
        #    | \_____         \
        #    |       \         \
        #  [GW1]     [GW2]    [Symmetric-GW]
        #    |         |           |
        # [ALPHA]    [BETA]     [GAMMA]

        await testing.wait_lengthy(check_derp_connection(alpha_client, DERP1_IP, True))
        await testing.wait_lengthy(check_derp_connection(beta_client, DERP1_IP, True))
        await testing.wait_lengthy(check_derp_connection(gamma_client, DERP1_IP, True))

        # Ping ALPHA --> BETA
        async with Ping(alpha_connection, CLIENT_BETA_IP) as ping:
            await testing.wait_long(ping.wait_for_next_ping())
        # Ping ALPHA --> GAMMA
        async with Ping(alpha_connection, CLIENT_GAMMA_IP) as ping:
            await testing.wait_long(ping.wait_for_next_ping())
        # Ping BETA --> GAMMA
        async with Ping(beta_connection, CLIENT_GAMMA_IP) as ping:
            await testing.wait_long(ping.wait_for_next_ping())
        # Ping GAMMA --> BETA
        async with Ping(gamma_connection, CLIENT_BETA_IP) as ping:
            await testing.wait_long(ping.wait_for_next_ping())

        # ==============================================================
        # Break BETA-DERP1 and GAMMA-DERP1 connections:
        #    ╔═════════╦═══════════╗
        # [DERP1]   [DERP2]     [DERP3]
        #    |\ \_____________
        #    | \_____         \
        #    |       x         x
        #  [GW1]     [GW2]    [Symmetric-GW]
        #    |         |           |
        # [ALPHA]    [BETA]     [GAMMA]
        #
        # (x - broken connection)

        # An iptables rule is placed in order to reject connections and
        # send a TCP reset to the client BETA
        await exit_stack.enter_async_context(
            beta_client.get_router().break_tcp_conn_to_host(DERP1_IP)
        )
        await exit_stack.enter_async_context(
            gamma_client.get_router().break_tcp_conn_to_host(DERP1_IP)
        )

        await testing.wait_lengthy(check_derp_connection(beta_client, DERP1_IP, False))
        await testing.wait_lengthy(check_derp_connection(gamma_client, DERP1_IP, False))

        # ==============================================================
        # Wait till BETA-DERP2 and GAMMA-DERP2 connect:
        #    ╔═════════╦═══════════╗
        # [DERP1]   [DERP2]     [DERP3]
        #    |\ \      |  \_____
        #    | * *     |        \
        #    |       x |       x \
        #  [GW1]     [GW2]    [Symmetric-GW]
        #    |         |           |
        # [ALPHA]    [BETA]     [GAMMA]
        #
        # (* - connection to the escaped client, but DERP does not know):

        await testing.wait_lengthy(check_derp_connection(alpha_client, DERP1_IP, True))
        await testing.wait_lengthy(check_derp_connection(beta_client, DERP2_IP, True))
        await testing.wait_lengthy(check_derp_connection(gamma_client, DERP2_IP, True))

        # ==============================================================
        # Break GAMMA-DERP2 connection:
        #    ╔═════════╦═══════════╗
        # [DERP1]   [DERP2]     [DERP3]
        #    |\ \      |  \_____
        #    | * *     |        \
        #    |       x |      x  x
        #  [GW1]     [GW2]    [Symmetric-GW]
        #    |         |           |
        # [ALPHA]    [BETA]     [GAMMA]

        await exit_stack.enter_async_context(
            gamma_client.get_router().break_tcp_conn_to_host(DERP2_IP)
        )
        await testing.wait_lengthy(check_derp_connection(gamma_client, DERP2_IP, False))

        # ==============================================================
        # Wait till GAMMA-DERP3 connect
        # Final state:
        #    ╔═════════╦═══════════╗
        # [DERP1]   [DERP2]     [DERP3]
        #    | \ \     | \         |
        #    |  * *    |  *        |
        #    |       x |       x x |
        #  [GW1]     [GW2]    [Symmetric-GW]
        #    |         |           |
        # [ALPHA]    [BETA]     [GAMMA]

        await testing.wait_lengthy(check_derp_connection(alpha_client, DERP1_IP, True))
        await testing.wait_lengthy(check_derp_connection(beta_client, DERP2_IP, True))
        await testing.wait_lengthy(check_derp_connection(gamma_client, DERP3_IP, True))

        # Ping ALPHA --> BETA
        async with Ping(alpha_connection, CLIENT_BETA_IP) as ping:
            await testing.wait_long(ping.wait_for_next_ping())
        # Ping ALPHA --> GAMMA
        async with Ping(alpha_connection, CLIENT_GAMMA_IP) as ping:
            await testing.wait_long(ping.wait_for_next_ping())
        # Ping BETA --> GAMMA
        async with Ping(beta_connection, CLIENT_GAMMA_IP) as ping:
            await testing.wait_long(ping.wait_for_next_ping())
        # Ping GAMMA --> BETA
        async with Ping(gamma_connection, CLIENT_BETA_IP) as ping:
            await testing.wait_long(ping.wait_for_next_ping())


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "adapter_type",
    [
        pytest.param(
            telio.AdapterType.BoringTun,
        ),
        pytest.param(
            telio.AdapterType.LinuxNativeWg,
            marks=pytest.mark.linux_native,
        ),
    ],
)
# test client reconnection
async def test_derp_restart(adapter_type: telio.AdapterType) -> None:
    async with AsyncExitStack() as exit_stack:
        DERP_SERVERS1 = [
            DERP_PRIMARY.copy(),
            DERP_SECONDARY.copy(),
            DERP_TERTIARY.copy(),
        ]
        DERP_SERVERS1[0]["weight"] = 1
        DERP_SERVERS1[1]["weight"] = 2
        DERP_SERVERS1[2]["weight"] = 3

        DERP_SERVERS2 = [
            DERP_PRIMARY.copy(),
            DERP_SECONDARY.copy(),
            DERP_TERTIARY.copy(),
        ]
        DERP_SERVERS2[0]["weight"] = 3
        DERP_SERVERS2[1]["weight"] = 1
        DERP_SERVERS2[2]["weight"] = 2

        DERP_SERVERS3 = [
            DERP_PRIMARY.copy(),
            DERP_SECONDARY.copy(),
            DERP_TERTIARY.copy(),
        ]
        DERP_SERVERS3[0]["weight"] = 3
        DERP_SERVERS3[1]["weight"] = 2
        DERP_SERVERS3[2]["weight"] = 1

        DERP1_IP = str(DERP_SERVERS1[0]["ipv4"])
        DERP2_IP = str(DERP_SERVERS1[1]["ipv4"])
        DERP3_IP = str(DERP_SERVERS1[2]["ipv4"])
        CLIENT_ALPHA_IP = "100.72.33.21"
        CLIENT_BETA_IP = "100.72.33.22"
        CLIENT_GAMMA_IP = "100.72.33.23"

        api = API()
        alpha = api.register(
            name="alpha",
            id="96ddb926-4b86-11ec-81d3-0242ac130003",
            private_key="IGm+42FLMMGZRaQvk6F3UPbl+T/CBk8W+NPoX2/AdlU=",
            public_key="41CCEssnYIh8/8D8YvbTfWEcFanG3D0I0z1tRcN1Lyc=",
        )
        beta = api.register(
            name="beta",
            id="7b4548ca-fe5a-4597-8513-896f38c6d6ae",
            private_key="SPFD84gPtBNc3iGY9Cdrj+mSCwBeh3mCMWfPaeWQolw=",
            public_key="Q1M3VKUcfTmGsrRzY6BpNds1yDIUvPVcs/2TySv/t1U=",
        )
        gamma = api.register(
            name="gamma",
            id="6b825055-91fa-41b7-ac65-78dbf397a2cd",
            private_key="WMsz2uwtYIlqDEfkGjLX7tz1hcK+ylecHvL+z0tAqWM=",
            public_key="sT82kS+0VFH6TPIlLqFzOJ7e4OOc8udFCZt1O9ZUv3k=",
        )
        api.assign_ip(alpha.id, CLIENT_ALPHA_IP)
        api.assign_ip(beta.id, CLIENT_BETA_IP)
        api.assign_ip(gamma.id, CLIENT_GAMMA_IP)

        beta.set_peer_firewall_settings(alpha.id, allow_incoming_connections=True)
        beta.set_peer_firewall_settings(gamma.id, allow_incoming_connections=True)
        gamma.set_peer_firewall_settings(alpha.id, allow_incoming_connections=True)
        gamma.set_peer_firewall_settings(beta.id, allow_incoming_connections=True)

        alpha_connection = await exit_stack.enter_async_context(
            new_connection_by_tag(ConnectionTag.DOCKER_CONE_CLIENT_1)
        )
        beta_connection = await exit_stack.enter_async_context(
            new_connection_by_tag(ConnectionTag.DOCKER_CONE_CLIENT_2)
        )
        gamma_connection = await exit_stack.enter_async_context(
            new_connection_by_tag(ConnectionTag.DOCKER_SYMMETRIC_CLIENT_1)
        )

        alpha_client = await exit_stack.enter_async_context(
            telio.run_meshnet(
                alpha_connection,
                alpha,
                api.get_meshmap(alpha.id, DERP_SERVERS1),
                adapter_type,
            )
        )
        beta_client = await exit_stack.enter_async_context(
            telio.run_meshnet(
                beta_connection,
                beta,
                api.get_meshmap(beta.id, DERP_SERVERS2),
            )
        )
        gamma_client = await exit_stack.enter_async_context(
            telio.run_meshnet(
                gamma_connection,
                gamma,
                api.get_meshmap(gamma.id, DERP_SERVERS3),
            )
        )

        await testing.wait_long(alpha_client.handshake(beta.public_key))
        await testing.wait_long(alpha_client.handshake(gamma.public_key))
        await testing.wait_long(beta_client.handshake(alpha.public_key))
        await testing.wait_long(beta_client.handshake(gamma.public_key))
        await testing.wait_long(gamma_client.handshake(alpha.public_key))
        await testing.wait_long(gamma_client.handshake(beta.public_key))

        # ==============================================================
        # Initial state:
        #
        #    ╔════════╦════════╗
        # [DERP1]  [DERP2]  [DERP3]
        #    |w1      |w1      |w1
        #    |        |        |
        #  [GW1]    [GW2]   [Symmetric-GW]
        #    |        |        |
        # [ALPHA]   [BETA]  [GAMMA]
        #
        # (w1: DERP->weight=1 for that client):

        await testing.wait_lengthy(check_derp_connection(alpha_client, DERP1_IP, True))
        await testing.wait_lengthy(check_derp_connection(beta_client, DERP2_IP, True))
        await testing.wait_lengthy(check_derp_connection(gamma_client, DERP3_IP, True))

        # Ping ALPHA --> BETA
        async with Ping(alpha_connection, CLIENT_BETA_IP) as ping:
            await testing.wait_long(ping.wait_for_next_ping())
        # Ping ALPHA --> GAMMA
        async with Ping(alpha_connection, CLIENT_GAMMA_IP) as ping:
            await testing.wait_long(ping.wait_for_next_ping())
        # Ping BETA --> GAMMA
        async with Ping(beta_connection, CLIENT_GAMMA_IP) as ping:
            await testing.wait_long(ping.wait_for_next_ping())
        # Ping GAMMA --> BETA
        async with Ping(gamma_connection, CLIENT_BETA_IP) as ping:
            await testing.wait_long(ping.wait_for_next_ping())

        # ==============================================================
        # DERP-1 restart:
        #
        #    ╔════════╦════════╗
        #    💀    [DERP2]  [DERP3]
        #      _____/ |w1      |w1
        #     /  w2   |        |
        #  [GW1]    [GW2]   [Symmetric-GW]
        #    |        |        |
        # [ALPHA]   [BETA]  [GAMMA]

        os.system("docker stop nat-lab-derp-01-1")
        await asyncio.sleep(1)
        os.system("docker start nat-lab-derp-01-1")

        await testing.wait_lengthy(check_derp_connection(alpha_client, DERP2_IP, True))
        await testing.wait_lengthy(check_derp_connection(beta_client, DERP2_IP, True))
        await testing.wait_lengthy(check_derp_connection(gamma_client, DERP3_IP, True))

        # Ping ALPHA --> BETA
        async with Ping(alpha_connection, CLIENT_BETA_IP) as ping:
            await testing.wait_long(ping.wait_for_next_ping())
        # Ping ALPHA --> GAMMA
        async with Ping(alpha_connection, CLIENT_GAMMA_IP) as ping:
            await testing.wait_long(ping.wait_for_next_ping())
        # Ping BETA --> GAMMA
        async with Ping(beta_connection, CLIENT_GAMMA_IP) as ping:
            await testing.wait_long(ping.wait_for_next_ping())
        # Ping GAMMA --> BETA
        async with Ping(gamma_connection, CLIENT_BETA_IP) as ping:
            await testing.wait_long(ping.wait_for_next_ping())

        # ==============================================================
        # DERP-2 restart
        #
        #    ╔════════╦════════╗
        # [DERP1]     💀    [DERP3]
        #    |w1        _____/ |w1
        #    |         /  w2   |
        #  [GW1]    [GW2]   [Symmetric-GW]
        #    |        |        |
        # [ALPHA]   [BETA]  [GAMMA]

        os.system("docker stop nat-lab-derp-02-1")
        await asyncio.sleep(1)
        os.system("docker start nat-lab-derp-02-1")

        await testing.wait_lengthy(check_derp_connection(alpha_client, DERP1_IP, True))
        await testing.wait_lengthy(check_derp_connection(beta_client, DERP3_IP, True))
        await testing.wait_lengthy(check_derp_connection(gamma_client, DERP3_IP, True))

        # Ping ALPHA --> BETA
        async with Ping(alpha_connection, CLIENT_BETA_IP) as ping:
            await testing.wait_long(ping.wait_for_next_ping())
        # Ping ALPHA --> GAMMA
        async with Ping(alpha_connection, CLIENT_GAMMA_IP) as ping:
            await testing.wait_long(ping.wait_for_next_ping())
        # Ping BETA --> GAMMA
        async with Ping(beta_connection, CLIENT_GAMMA_IP) as ping:
            await testing.wait_long(ping.wait_for_next_ping())
        # Ping GAMMA --> BETA
        async with Ping(gamma_connection, CLIENT_BETA_IP) as ping:
            await testing.wait_long(ping.wait_for_next_ping())

        # ==============================================================
        # DERP-3 restart
        #
        #    ╔════════╦════════╗
        # [DERP1]  [DERP2]     💀
        #    |w1    w1| \_____
        #    |        |   w2  \
        #  [GW1]    [GW2]   [Symmetric-GW]
        #    |        |        |
        # [ALPHA]   [BETA]  [GAMMA]

        os.system("docker stop nat-lab-derp-03-1")
        await asyncio.sleep(1)
        os.system("docker start nat-lab-derp-03-1")

        await testing.wait_lengthy(check_derp_connection(alpha_client, DERP1_IP, True))
        await testing.wait_lengthy(check_derp_connection(beta_client, DERP2_IP, True))
        await testing.wait_lengthy(check_derp_connection(gamma_client, DERP2_IP, True))

        # Ping ALPHA --> BETA
        async with Ping(alpha_connection, CLIENT_BETA_IP) as ping:
            await testing.wait_long(ping.wait_for_next_ping())
        # Ping ALPHA --> GAMMA
        async with Ping(alpha_connection, CLIENT_GAMMA_IP) as ping:
            await testing.wait_long(ping.wait_for_next_ping())
        # Ping BETA --> GAMMA
        async with Ping(beta_connection, CLIENT_GAMMA_IP) as ping:
            await testing.wait_long(ping.wait_for_next_ping())
        # Ping GAMMA --> BETA
        async with Ping(gamma_connection, CLIENT_BETA_IP) as ping:
            await testing.wait_long(ping.wait_for_next_ping())

        # ==============================================================
        # Final state:
        #
        #    ╔════════╦════════╗
        # [DERP1]  [DERP2]  [DERP3]
        #    |w1    w1| \_____
        #    |        |   w2  \
        #  [GW1]    [GW2]   [Symmetric-GW]
        #    |        |        |
        # [ALPHA]   [BETA]  [GAMMA]
