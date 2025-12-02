import asyncio
import os
import pytest
from contextlib import AsyncExitStack, asynccontextmanager
from copy import deepcopy
from tests.config import DERP_PRIMARY, DERP_SECONDARY, DERP_TERTIARY, DERP_SERVERS
from tests.helpers import SetupParameters, setup_mesh_nodes
from tests.utils.bindings import RelayState, FeatureDerp, default_features
from tests.utils.connection import ConnectionTag
from tests.utils.ping import ping
from typing import List

DERP1_IP = str(DERP_PRIMARY.ipv4)
DERP2_IP = str(DERP_SECONDARY.ipv4)
DERP3_IP = str(DERP_TERTIARY.ipv4)


def _build_parameters(
    connection_tag: List[ConnectionTag], enable_poll_keepalives: bool
) -> List[SetupParameters]:
    features = default_features()
    if enable_poll_keepalives:
        assert features
        features.derp = FeatureDerp(
            tcp_keepalive=120,
            derp_keepalive=15,
            poll_keepalive=True,
            enable_polling=False,
            use_built_in_root_certificates=False,
        )
    return [
        SetupParameters(
            connection_tag=connection_tag,
            features=features,
        )
        for connection_tag in connection_tag
    ]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "setup_params",
    [
        _build_parameters(
            [ConnectionTag.DOCKER_CONE_CLIENT_1, ConnectionTag.DOCKER_CONE_CLIENT_2],
            False,
        ),
        _build_parameters(
            [ConnectionTag.DOCKER_CONE_CLIENT_1, ConnectionTag.DOCKER_CONE_CLIENT_2],
            True,
        ),
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
        await ping(alpha_connection, beta.ip_addresses[0])

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
            DERP1_IP, [RelayState.DISCONNECTED, RelayState.CONNECTING]
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

        await beta_client.wait_for_state_derp(DERP2_IP, [RelayState.CONNECTED])

        # Ping peer to check if connection truly works
        await ping(alpha_connection, beta.ip_addresses[0])


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "setup_params",
    [
        _build_parameters(
            [
                ConnectionTag.DOCKER_CONE_CLIENT_1,
                ConnectionTag.DOCKER_CONE_CLIENT_2,
                ConnectionTag.DOCKER_SYMMETRIC_CLIENT_1,
            ],
            False,
        ),
        _build_parameters(
            [
                ConnectionTag.DOCKER_CONE_CLIENT_1,
                ConnectionTag.DOCKER_CONE_CLIENT_2,
                ConnectionTag.DOCKER_SYMMETRIC_CLIENT_1,
            ],
            True,
        ),
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
        await ping(alpha_connection, beta.ip_addresses[0])

        # Ping ALPHA --> GAMMA
        await ping(alpha_connection, gamma.ip_addresses[0])

        # Ping BETA --> GAMMA
        await ping(beta_connection, gamma.ip_addresses[0])

        # Ping GAMMA --> BETA
        await ping(gamma_connection, beta.ip_addresses[0])

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
            DERP1_IP, [RelayState.DISCONNECTED, RelayState.CONNECTING]
        )
        await gamma_client.wait_for_state_derp(
            DERP1_IP, [RelayState.DISCONNECTED, RelayState.CONNECTING]
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
            alpha_client.wait_for_state_derp(DERP1_IP, [RelayState.CONNECTED]),
            beta_client.wait_for_state_derp(DERP2_IP, [RelayState.CONNECTED]),
            gamma_client.wait_for_state_derp(DERP2_IP, [RelayState.CONNECTED]),
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
            DERP2_IP, [RelayState.DISCONNECTED, RelayState.CONNECTING]
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
            alpha_client.wait_for_state_derp(DERP1_IP, [RelayState.CONNECTED]),
            beta_client.wait_for_state_derp(DERP2_IP, [RelayState.CONNECTED]),
            gamma_client.wait_for_state_derp(DERP3_IP, [RelayState.CONNECTED]),
        )

        # Ping ALPHA --> BETA
        await ping(alpha_connection, beta.ip_addresses[0])

        # Ping ALPHA --> GAMMA
        await ping(alpha_connection, gamma.ip_addresses[0])

        # Ping BETA --> GAMMA
        await ping(beta_connection, gamma.ip_addresses[0])

        # Ping GAMMA --> BETA
        await ping(gamma_connection, beta.ip_addresses[0])


@asynccontextmanager
async def stop_container(container_name: str):
    try:
        os.system(f"docker stop {container_name}")
        yield
    finally:
        os.system(f"docker start {container_name}")


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "setup_params",
    [
        _build_parameters(
            [
                ConnectionTag.DOCKER_CONE_CLIENT_1,
                ConnectionTag.DOCKER_CONE_CLIENT_2,
                ConnectionTag.DOCKER_SYMMETRIC_CLIENT_1,
            ],
            False,
        ),
        _build_parameters(
            [
                ConnectionTag.DOCKER_CONE_CLIENT_1,
                ConnectionTag.DOCKER_CONE_CLIENT_2,
                ConnectionTag.DOCKER_SYMMETRIC_CLIENT_1,
            ],
            True,
        ),
    ],
)
async def test_derp_restart(setup_params: List[SetupParameters]) -> None:
    async with AsyncExitStack() as exit_stack:
        DERP_SERVERS1 = [
            deepcopy(DERP_PRIMARY),
            deepcopy(DERP_SECONDARY),
            deepcopy(DERP_TERTIARY),
        ]
        DERP_SERVERS1[0].weight = 1
        DERP_SERVERS1[1].weight = 2
        DERP_SERVERS1[2].weight = 3

        DERP_SERVERS2 = [
            deepcopy(DERP_PRIMARY),
            deepcopy(DERP_SECONDARY),
            deepcopy(DERP_TERTIARY),
        ]
        DERP_SERVERS2[0].weight = 3
        DERP_SERVERS2[1].weight = 1
        DERP_SERVERS2[2].weight = 2

        DERP_SERVERS3 = [
            deepcopy(DERP_PRIMARY),
            deepcopy(DERP_SECONDARY),
            deepcopy(DERP_TERTIARY),
        ]
        DERP_SERVERS3[0].weight = 3
        DERP_SERVERS3[1].weight = 2
        DERP_SERVERS3[2].weight = 1

        _DERP1_IP = str(DERP_SERVERS1[0].ipv4)
        _DERP2_IP = str(DERP_SERVERS1[1].ipv4)
        _DERP3_IP = str(DERP_SERVERS1[2].ipv4)

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
        await ping(alpha_connection, beta.ip_addresses[0])

        # Ping ALPHA --> GAMMA
        await ping(alpha_connection, gamma.ip_addresses[0])

        # Ping BETA --> GAMMA
        await ping(beta_connection, gamma.ip_addresses[0])

        # Ping GAMMA --> BETA
        await ping(gamma_connection, beta.ip_addresses[0])

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
        async with stop_container("nat-lab-derp-01-1"):
            await asyncio.gather(
                alpha_client.wait_for_state_derp(_DERP2_IP, [RelayState.CONNECTED]),
                beta_client.wait_for_state_derp(_DERP2_IP, [RelayState.CONNECTED]),
                gamma_client.wait_for_state_derp(_DERP3_IP, [RelayState.CONNECTED]),
            )

        # Ping ALPHA --> BETA
        await ping(alpha_connection, beta.ip_addresses[0])

        # Ping ALPHA --> GAMMA
        await ping(alpha_connection, gamma.ip_addresses[0])

        # Ping BETA --> GAMMA
        await ping(beta_connection, gamma.ip_addresses[0])

        # Ping GAMMA --> BETA
        await ping(gamma_connection, beta.ip_addresses[0])

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

        async with stop_container("nat-lab-derp-02-1"):
            await asyncio.gather(
                alpha_client.wait_for_state_derp(_DERP1_IP, [RelayState.CONNECTED]),
                beta_client.wait_for_state_derp(_DERP3_IP, [RelayState.CONNECTED]),
                gamma_client.wait_for_state_derp(_DERP3_IP, [RelayState.CONNECTED]),
            )

        # Ping ALPHA --> BETA
        await ping(alpha_connection, beta.ip_addresses[0])

        # Ping ALPHA --> GAMMA
        await ping(alpha_connection, gamma.ip_addresses[0])

        # Ping BETA --> GAMMA
        await ping(beta_connection, gamma.ip_addresses[0])

        # Ping GAMMA --> BETA
        await ping(gamma_connection, beta.ip_addresses[0])

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

        async with stop_container("nat-lab-derp-03-1"):
            await asyncio.gather(
                alpha_client.wait_for_state_derp(_DERP1_IP, [RelayState.CONNECTED]),
                beta_client.wait_for_state_derp(_DERP2_IP, [RelayState.CONNECTED]),
                gamma_client.wait_for_state_derp(_DERP2_IP, [RelayState.CONNECTED]),
            )

        # Ping ALPHA --> BETA
        await ping(alpha_connection, beta.ip_addresses[0])

        # Ping ALPHA --> GAMMA
        await ping(alpha_connection, gamma.ip_addresses[0])

        # Ping BETA --> GAMMA
        await ping(beta_connection, gamma.ip_addresses[0])

        # Ping GAMMA --> BETA
        await ping(gamma_connection, beta.ip_addresses[0])

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

        await ping(alpha_connection, beta.ip_addresses[0])

        # Insert iptables rules to block connection for every Derp server
        async with AsyncExitStack() as exit_stack_iptables:
            for derp_server in DERP_SERVERS:
                await exit_stack_iptables.enter_async_context(
                    beta_client.get_router().break_tcp_conn_to_host(
                        str(derp_server.ipv4)
                    )
                )

            # Every derp connection should be broken at this point
            await beta_client.wait_for_every_derp_disconnection()

        # iptables rules are dropped already
        await beta_client.wait_for_state_on_any_derp([RelayState.CONNECTED])

        # Ping peer to check if connection truly works
        await ping(alpha_connection, beta.ip_addresses[0])


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "setup_params",
    [
        _build_parameters([ConnectionTag.DOCKER_CONE_CLIENT_1], False),
        _build_parameters([ConnectionTag.DOCKER_CONE_CLIENT_1], True),
    ],
)
async def test_derp_reconnect_1client(setup_params: List[SetupParameters]) -> None:
    async with AsyncExitStack() as exit_stack:
        env = await setup_mesh_nodes(exit_stack, setup_params)
        alpha_client = env.clients[0]
        assert alpha_client

        # an iptables rule is placed in order to reject connections and
        # send a TCP reset to the client BETA
        await exit_stack.enter_async_context(
            alpha_client.get_router().break_tcp_conn_to_host(DERP1_IP)
        )

        # Wait till connection is broken
        await alpha_client.wait_for_state_derp(
            DERP1_IP, [RelayState.DISCONNECTED, RelayState.CONNECTING]
        )

        await alpha_client.wait_for_state_derp(DERP2_IP, [RelayState.CONNECTED])
