from utils import Ping
from config import DERP_PRIMARY, DERP_SECONDARY, DERP_TERTIARY, DERP_SERVERS
from contextlib import AsyncExitStack
from mesh_api import API
from utils import ConnectionTag, new_connection_by_tag, testing
from derp_cli import check_derp_connection
import asyncio
import os
import pytest
import telio


@pytest.mark.asyncio
# test client reconnection
async def test_derp_reconnect_2clients() -> None:
    # TODO test tcp keepalive
    async with AsyncExitStack() as exit_stack:
        DERP1_IP = str(DERP_PRIMARY["ipv4"])
        DERP2_IP = str(DERP_SECONDARY["ipv4"])

        api = API()
        (alpha, beta) = api.default_config_two_nodes()

        # ALPHA will use the cone nat : "nat-lab-cone-client-01-1
        alpha_connection = await exit_stack.enter_async_context(
            new_connection_by_tag(ConnectionTag.DOCKER_CONE_CLIENT_1)
        )

        # BETA will use the cone nat : "nat-lab-cone-client-02-1
        beta_connection = await exit_stack.enter_async_context(
            new_connection_by_tag(ConnectionTag.DOCKER_CONE_CLIENT_2)
        )

        alpha_client = await exit_stack.enter_async_context(
            telio.Client(alpha_connection, alpha,).run_meshnet(
                api.get_meshmap(alpha.id),
            )
        )

        beta_client = await exit_stack.enter_async_context(
            telio.Client(beta_connection, beta,).run_meshnet(
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

        async with Ping(alpha_connection, beta.ip_addresses[0]).run() as ping:
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
        async with Ping(alpha_connection, beta.ip_addresses[0]).run() as ping:
            await testing.wait_long(ping.wait_for_next_ping())


@pytest.mark.asyncio
# test client reconnection
async def test_derp_reconnect_3clients() -> None:
    # TODO test tcp keepalive
    async with AsyncExitStack() as exit_stack:
        DERP1_IP = str(DERP_PRIMARY["ipv4"])
        DERP2_IP = str(DERP_SECONDARY["ipv4"])
        DERP3_IP = str(DERP_TERTIARY["ipv4"])

        api = API()
        (alpha, beta, gamma) = api.default_config_three_nodes()

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
            telio.Client(alpha_connection, alpha,).run_meshnet(
                api.get_meshmap(alpha.id),
            )
        )
        beta_client = await exit_stack.enter_async_context(
            telio.Client(beta_connection, beta,).run_meshnet(
                api.get_meshmap(beta.id),
            )
        )
        gamma_client = await exit_stack.enter_async_context(
            telio.Client(gamma_connection, gamma,).run_meshnet(
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
        async with Ping(alpha_connection, beta.ip_addresses[0]).run() as ping:
            await testing.wait_long(ping.wait_for_next_ping())
        # Ping ALPHA --> GAMMA
        async with Ping(alpha_connection, gamma.ip_addresses[0]).run() as ping:
            await testing.wait_long(ping.wait_for_next_ping())
        # Ping BETA --> GAMMA
        async with Ping(beta_connection, gamma.ip_addresses[0]).run() as ping:
            await testing.wait_long(ping.wait_for_next_ping())
        # Ping GAMMA --> BETA
        async with Ping(gamma_connection, beta.ip_addresses[0]).run() as ping:
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
        async with Ping(alpha_connection, beta.ip_addresses[0]).run() as ping:
            await testing.wait_long(ping.wait_for_next_ping())
        # Ping ALPHA --> GAMMA
        async with Ping(alpha_connection, gamma.ip_addresses[0]).run() as ping:
            await testing.wait_long(ping.wait_for_next_ping())
        # Ping BETA --> GAMMA
        async with Ping(beta_connection, gamma.ip_addresses[0]).run() as ping:
            await testing.wait_long(ping.wait_for_next_ping())
        # Ping GAMMA --> BETA
        async with Ping(gamma_connection, beta.ip_addresses[0]).run() as ping:
            await testing.wait_long(ping.wait_for_next_ping())


@pytest.mark.asyncio
# test client reconnection
async def test_derp_restart() -> None:
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

        api = API()
        (alpha, beta, gamma) = api.default_config_three_nodes()

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
            telio.Client(alpha_connection, alpha,).run_meshnet(
                api.get_meshmap(alpha.id, DERP_SERVERS1),
            )
        )
        beta_client = await exit_stack.enter_async_context(
            telio.Client(beta_connection, beta,).run_meshnet(
                api.get_meshmap(beta.id, DERP_SERVERS2),
            )
        )
        gamma_client = await exit_stack.enter_async_context(
            telio.Client(gamma_connection, gamma,).run_meshnet(
                api.get_meshmap(gamma.id, DERP_SERVERS3),
            )
        )

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

        await testing.wait_long(alpha_client.handshake(beta.public_key))
        await testing.wait_long(alpha_client.handshake(gamma.public_key))
        await testing.wait_long(beta_client.handshake(alpha.public_key))
        await testing.wait_long(beta_client.handshake(gamma.public_key))
        await testing.wait_long(gamma_client.handshake(alpha.public_key))
        await testing.wait_long(gamma_client.handshake(beta.public_key))

        # Ping ALPHA --> BETA
        async with Ping(alpha_connection, beta.ip_addresses[0]).run() as ping:
            await testing.wait_long(ping.wait_for_next_ping())
        # Ping ALPHA --> GAMMA
        async with Ping(alpha_connection, gamma.ip_addresses[0]).run() as ping:
            await testing.wait_long(ping.wait_for_next_ping())
        # Ping BETA --> GAMMA
        async with Ping(beta_connection, gamma.ip_addresses[0]).run() as ping:
            await testing.wait_long(ping.wait_for_next_ping())
        # Ping GAMMA --> BETA
        async with Ping(gamma_connection, beta.ip_addresses[0]).run() as ping:
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
        async with Ping(alpha_connection, beta.ip_addresses[0]).run() as ping:
            await testing.wait_long(ping.wait_for_next_ping())
        # Ping ALPHA --> GAMMA
        async with Ping(alpha_connection, gamma.ip_addresses[0]).run() as ping:
            await testing.wait_long(ping.wait_for_next_ping())
        # Ping BETA --> GAMMA
        async with Ping(beta_connection, gamma.ip_addresses[0]).run() as ping:
            await testing.wait_long(ping.wait_for_next_ping())
        # Ping GAMMA --> BETA
        async with Ping(gamma_connection, beta.ip_addresses[0]).run() as ping:
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
        async with Ping(alpha_connection, beta.ip_addresses[0]).run() as ping:
            await testing.wait_long(ping.wait_for_next_ping())
        # Ping ALPHA --> GAMMA
        async with Ping(alpha_connection, gamma.ip_addresses[0]).run() as ping:
            await testing.wait_long(ping.wait_for_next_ping())
        # Ping BETA --> GAMMA
        async with Ping(beta_connection, gamma.ip_addresses[0]).run() as ping:
            await testing.wait_long(ping.wait_for_next_ping())
        # Ping GAMMA --> BETA
        async with Ping(gamma_connection, beta.ip_addresses[0]).run() as ping:
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
        async with Ping(alpha_connection, beta.ip_addresses[0]).run() as ping:
            await testing.wait_long(ping.wait_for_next_ping())
        # Ping ALPHA --> GAMMA
        async with Ping(alpha_connection, gamma.ip_addresses[0]).run() as ping:
            await testing.wait_long(ping.wait_for_next_ping())
        # Ping BETA --> GAMMA
        async with Ping(beta_connection, gamma.ip_addresses[0]).run() as ping:
            await testing.wait_long(ping.wait_for_next_ping())
        # Ping GAMMA --> BETA
        async with Ping(gamma_connection, beta.ip_addresses[0]).run() as ping:
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


@pytest.mark.asyncio
async def test_derp_server_list_exhaustion() -> None:
    async with AsyncExitStack() as exit_stack:
        api = API()
        (alpha, beta) = api.default_config_two_nodes()

        alpha_connection = await exit_stack.enter_async_context(
            new_connection_by_tag(ConnectionTag.DOCKER_CONE_CLIENT_1)
        )
        beta_connection = await exit_stack.enter_async_context(
            new_connection_by_tag(ConnectionTag.DOCKER_CONE_CLIENT_2)
        )

        alpha_client = await exit_stack.enter_async_context(
            telio.Client(alpha_connection, alpha,).run_meshnet(
                api.get_meshmap(alpha.id),
            )
        )
        beta_client = await exit_stack.enter_async_context(
            telio.Client(beta_connection, beta,).run_meshnet(
                api.get_meshmap(beta.id),
            )
        )

        await testing.wait_long(alpha_client.handshake(beta.public_key))
        await testing.wait_long(beta_client.handshake(alpha.public_key))

        await testing.wait_lengthy(
            check_derp_connection(alpha_client, str(DERP_SERVERS[0]["ipv4"]), True)
        )
        await testing.wait_lengthy(
            check_derp_connection(beta_client, str(DERP_SERVERS[0]["ipv4"]), True)
        )

        async with Ping(alpha_connection, beta.ip_addresses[0]).run() as ping:
            await testing.wait_long(ping.wait_for_next_ping())

        # Insert iptables rules to block connection for every Derp server
        async with AsyncExitStack() as exit_stack_iptables:
            for derp_server in DERP_SERVERS:
                await exit_stack_iptables.enter_async_context(
                    beta_client.get_router().break_tcp_conn_to_host(
                        str(derp_server["ipv4"])
                    )
                )

            # Wait till connection is broken
            await testing.wait_lengthy(
                beta_client.wait_for_any_derp_state(
                    [telio.State.Connecting, telio.State.Disconnected]
                )
            )

        # iptables rules are dropped already
        await testing.wait_lengthy(
            beta_client.wait_for_any_derp_state([telio.State.Connected])
        )

        # Ping peer to check if connection truly works
        async with Ping(alpha_connection, beta.ip_addresses[0]).run() as ping:
            await testing.wait_long(ping.wait_for_next_ping())
