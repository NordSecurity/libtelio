import asyncio
import os
import pytest
from config import DERP_PRIMARY, DERP_SECONDARY, DERP_TERTIARY, DERP_SERVERS
from contextlib import AsyncExitStack
from helpers import SetupParameters, setup_mesh_nodes
from telio import State
from typing import List
from utils.connection_util import ConnectionTag
from utils.ping import Ping

DERP1_IP = str(DERP_PRIMARY["ipv4"])
DERP2_IP = str(DERP_SECONDARY["ipv4"])
DERP3_IP = str(DERP_TERTIARY["ipv4"])


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "setup_params",
    [
        [
            SetupParameters(connection_tag=ConnectionTag.DOCKER_CONE_CLIENT_1),
            SetupParameters(connection_tag=ConnectionTag.DOCKER_CONE_CLIENT_2),
        ],
    ],
)
async def test_derp_reconnect_2clients(setup_params: List[SetupParameters]) -> None:
    # TODO test tcp keepalive
    async with AsyncExitStack() as exit_stack:
        env = await setup_mesh_nodes(exit_stack, setup_params)
        _, beta = env.nodes
        alpha_connection, _ = [conn.connection for conn in env.connections]
        _, beta_client = env.clients

        # ==============================================================
        # Initial state (ping test 1):
        # [DERP1]===[DERP2]
        #     /  \___
        #  [GW1]     [GW2]
        #   /           \
        # [ALPHA]     [BETA]

        async with Ping(alpha_connection, beta.ip_addresses[0]).run() as ping:
            await ping.wait_for_next_ping()

        # ==============================================================
        # Break the connection:
        #
        # [DERP1]===[DERP2]
        #     /      X
        #  [GW1]     [GW2]
        #   /           \
        # [ALPHA]     [BETA]

        # an iptables rule is placed in order to reject connections and
        # send a TCP reset to the client BETA
        await exit_stack.enter_async_context(
            beta_client.get_router().break_tcp_conn_to_host(DERP1_IP)
        )

        # Wait till connection is broken
        await beta_client.wait_for_state_derp(
            DERP1_IP, [State.Disconnected, State.Connecting]
        )

        # ==============================================================
        # Wait till new connection is established
        # Final state (ping test 2):
        #
        # [DERP1]===[DERP2]
        #     /       \
        #  [GW1]     [GW2]
        #   /           \
        # [ALPHA]     [BETA]

        await beta_client.wait_for_state_derp(DERP2_IP, [State.Connected])

        # Ping peer to check if connection truly works
        async with Ping(alpha_connection, beta.ip_addresses[0]).run() as ping:
            await ping.wait_for_next_ping()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "setup_params",
    [
        [
            SetupParameters(connection_tag=ConnectionTag.DOCKER_CONE_CLIENT_1),
            SetupParameters(connection_tag=ConnectionTag.DOCKER_CONE_CLIENT_2),
            SetupParameters(connection_tag=ConnectionTag.DOCKER_SYMMETRIC_CLIENT_1),
        ],
    ],
)
async def test_derp_reconnect_3clients(setup_params: List[SetupParameters]) -> None:
    # TODO test tcp keepalive
    async with AsyncExitStack() as exit_stack:
        env = await setup_mesh_nodes(exit_stack, setup_params)
        _, beta, gamma = env.nodes
        alpha_client, beta_client, gamma_client = env.clients
        alpha_connection, beta_connection, gamma_connection = [
            conn.connection for conn in env.connections
        ]

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

        # Ping ALPHA --> BETA
        async with Ping(alpha_connection, beta.ip_addresses[0]).run() as ping:
            await ping.wait_for_next_ping()
        # Ping ALPHA --> GAMMA
        async with Ping(alpha_connection, gamma.ip_addresses[0]).run() as ping:
            await ping.wait_for_next_ping()
        # Ping BETA --> GAMMA
        async with Ping(beta_connection, gamma.ip_addresses[0]).run() as ping:
            await ping.wait_for_next_ping()
        # Ping GAMMA --> BETA
        async with Ping(gamma_connection, beta.ip_addresses[0]).run() as ping:
            await ping.wait_for_next_ping()

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

        await beta_client.wait_for_state_derp(
            DERP1_IP, [State.Disconnected, State.Connecting]
        )
        await gamma_client.wait_for_state_derp(
            DERP1_IP, [State.Disconnected, State.Connecting]
        )

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

        await asyncio.gather(
            alpha_client.wait_for_state_derp(DERP1_IP, [State.Connected]),
            beta_client.wait_for_state_derp(DERP2_IP, [State.Connected]),
            gamma_client.wait_for_state_derp(DERP2_IP, [State.Connected]),
        )

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
        await gamma_client.wait_for_state_derp(
            DERP2_IP, [State.Disconnected, State.Connecting]
        )

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

        await asyncio.gather(
            alpha_client.wait_for_state_derp(DERP1_IP, [State.Connected]),
            beta_client.wait_for_state_derp(DERP2_IP, [State.Connected]),
            gamma_client.wait_for_state_derp(DERP3_IP, [State.Connected]),
        )

        # Ping ALPHA --> BETA
        async with Ping(alpha_connection, beta.ip_addresses[0]).run() as ping:
            await ping.wait_for_next_ping()
        # Ping ALPHA --> GAMMA
        async with Ping(alpha_connection, gamma.ip_addresses[0]).run() as ping:
            await ping.wait_for_next_ping()
        # Ping BETA --> GAMMA
        async with Ping(beta_connection, gamma.ip_addresses[0]).run() as ping:
            await ping.wait_for_next_ping()
        # Ping GAMMA --> BETA
        async with Ping(gamma_connection, beta.ip_addresses[0]).run() as ping:
            await ping.wait_for_next_ping()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "setup_params",
    [
        [
            SetupParameters(connection_tag=ConnectionTag.DOCKER_CONE_CLIENT_1),
            SetupParameters(connection_tag=ConnectionTag.DOCKER_CONE_CLIENT_2),
            SetupParameters(connection_tag=ConnectionTag.DOCKER_SYMMETRIC_CLIENT_1),
        ],
    ],
)
async def test_derp_restart(setup_params: List[SetupParameters]) -> None:
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

        _DERP1_IP = str(DERP_SERVERS1[0]["ipv4"])
        _DERP2_IP = str(DERP_SERVERS1[1]["ipv4"])
        _DERP3_IP = str(DERP_SERVERS1[2]["ipv4"])

        setup_params[0].derp_servers = DERP_SERVERS1
        setup_params[1].derp_servers = DERP_SERVERS2
        setup_params[2].derp_servers = DERP_SERVERS3

        env = await setup_mesh_nodes(exit_stack, setup_params)
        _, beta, gamma = env.nodes
        alpha_client, beta_client, gamma_client = env.clients
        alpha_connection, beta_connection, gamma_connection = [
            conn.connection for conn in env.connections
        ]

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

        # Ping ALPHA --> BETA
        async with Ping(alpha_connection, beta.ip_addresses[0]).run() as ping:
            await ping.wait_for_next_ping()
        # Ping ALPHA --> GAMMA
        async with Ping(alpha_connection, gamma.ip_addresses[0]).run() as ping:
            await ping.wait_for_next_ping()
        # Ping BETA --> GAMMA
        async with Ping(beta_connection, gamma.ip_addresses[0]).run() as ping:
            await ping.wait_for_next_ping()
        # Ping GAMMA --> BETA
        async with Ping(gamma_connection, beta.ip_addresses[0]).run() as ping:
            await ping.wait_for_next_ping()

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

        os.system("docker restart nat-lab-derp-01-1")

        await asyncio.gather(
            alpha_client.wait_for_state_derp(_DERP2_IP, [State.Connected]),
            beta_client.wait_for_state_derp(_DERP2_IP, [State.Connected]),
            gamma_client.wait_for_state_derp(_DERP3_IP, [State.Connected]),
        )

        # Ping ALPHA --> BETA
        async with Ping(alpha_connection, beta.ip_addresses[0]).run() as ping:
            await ping.wait_for_next_ping()
        # Ping ALPHA --> GAMMA
        async with Ping(alpha_connection, gamma.ip_addresses[0]).run() as ping:
            await ping.wait_for_next_ping()
        # Ping BETA --> GAMMA
        async with Ping(beta_connection, gamma.ip_addresses[0]).run() as ping:
            await ping.wait_for_next_ping()
        # Ping GAMMA --> BETA
        async with Ping(gamma_connection, beta.ip_addresses[0]).run() as ping:
            await ping.wait_for_next_ping()

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

        os.system("docker restart nat-lab-derp-02-1")

        await asyncio.gather(
            alpha_client.wait_for_state_derp(_DERP1_IP, [State.Connected]),
            beta_client.wait_for_state_derp(_DERP3_IP, [State.Connected]),
            gamma_client.wait_for_state_derp(_DERP3_IP, [State.Connected]),
        )

        # Ping ALPHA --> BETA
        async with Ping(alpha_connection, beta.ip_addresses[0]).run() as ping:
            await ping.wait_for_next_ping()
        # Ping ALPHA --> GAMMA
        async with Ping(alpha_connection, gamma.ip_addresses[0]).run() as ping:
            await ping.wait_for_next_ping()
        # Ping BETA --> GAMMA
        async with Ping(beta_connection, gamma.ip_addresses[0]).run() as ping:
            await ping.wait_for_next_ping()
        # Ping GAMMA --> BETA
        async with Ping(gamma_connection, beta.ip_addresses[0]).run() as ping:
            await ping.wait_for_next_ping()

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

        os.system("docker restart nat-lab-derp-03-1")

        await asyncio.gather(
            alpha_client.wait_for_state_derp(_DERP1_IP, [State.Connected]),
            beta_client.wait_for_state_derp(_DERP2_IP, [State.Connected]),
            gamma_client.wait_for_state_derp(_DERP2_IP, [State.Connected]),
        )

        # Ping ALPHA --> BETA
        async with Ping(alpha_connection, beta.ip_addresses[0]).run() as ping:
            await ping.wait_for_next_ping()
        # Ping ALPHA --> GAMMA
        async with Ping(alpha_connection, gamma.ip_addresses[0]).run() as ping:
            await ping.wait_for_next_ping()
        # Ping BETA --> GAMMA
        async with Ping(beta_connection, gamma.ip_addresses[0]).run() as ping:
            await ping.wait_for_next_ping()
        # Ping GAMMA --> BETA
        async with Ping(gamma_connection, beta.ip_addresses[0]).run() as ping:
            await ping.wait_for_next_ping()

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
@pytest.mark.parametrize(
    "setup_params",
    [
        [
            SetupParameters(connection_tag=ConnectionTag.DOCKER_CONE_CLIENT_1),
            SetupParameters(connection_tag=ConnectionTag.DOCKER_CONE_CLIENT_2),
        ],
    ],
)
async def test_derp_server_list_exhaustion(setup_params: List[SetupParameters]) -> None:
    async with AsyncExitStack() as exit_stack:
        env = await setup_mesh_nodes(exit_stack, setup_params)
        _, beta = env.nodes
        _, beta_client = env.clients
        alpha_connection, _ = [conn.connection for conn in env.connections]

        async with Ping(alpha_connection, beta.ip_addresses[0]).run() as ping:
            await ping.wait_for_next_ping()

        # Insert iptables rules to block connection for every Derp server
        async with AsyncExitStack() as exit_stack_iptables:
            for derp_server in DERP_SERVERS:
                await exit_stack_iptables.enter_async_context(
                    beta_client.get_router().break_tcp_conn_to_host(
                        str(derp_server["ipv4"])
                    )
                )

            # Every derp connection should be broken at this point
            await beta_client.wait_for_every_derp_disconnection()

        # iptables rules are dropped already
        await beta_client.wait_for_state_on_any_derp([State.Connected])

        # Ping peer to check if connection truly works
        async with Ping(alpha_connection, beta.ip_addresses[0]).run() as ping:
            await ping.wait_for_next_ping()
