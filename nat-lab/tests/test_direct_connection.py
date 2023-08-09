import asyncio
import pytest
import telio
from config import DERP_SERVERS
from contextlib import AsyncExitStack, asynccontextmanager
from dataclasses import dataclass
from mesh_api import API, Node
from telio import PathType, State, AdapterType
from telio_features import TelioFeatures, Direct
from typing import List, AsyncIterator, Tuple, Optional
from utils import testing
from utils.connection import Connection
from utils.connection_util import (
    ConnectionTag,
    new_connection_with_tracker_and_gw,
    ConnectionTracker,
    generate_connection_tracker_config,
    ConnectionLimits,
)
from utils.ping import Ping

ANY_PROVIDERS = ["local", "stun"]
LOCAL_PROVIDER = ["local"]
STUN_PROVIDER = ["stun"]
UPNP_PROVIDER = ["upnp"]

DOCKER_CONE_GW_2_IP = "10.0.254.2"
DOCKER_FULLCONE_GW_1_IP = "10.0.254.9"
DOCKER_FULLCONE_GW_2_IP = "10.0.254.6"
DOCKER_OPEN_INTERNET_CLIENT_1_IP = "10.0.11.2"
DOCKER_OPEN_INTERNET_CLIENT_2_IP = "10.0.11.3"
DOCKER_SYMMETRIC_GW_1_IP = "10.0.254.3"
DOCKER_UPNP_CLIENT_2_IP = "10.0.254.12"

UHP_conn_client_types = [
    (
        STUN_PROVIDER,
        ConnectionTag.DOCKER_FULLCONE_CLIENT_1,
        ConnectionTag.DOCKER_FULLCONE_CLIENT_2,
        DOCKER_FULLCONE_GW_2_IP,
    ),
    (
        STUN_PROVIDER,
        ConnectionTag.DOCKER_SYMMETRIC_CLIENT_1,
        ConnectionTag.DOCKER_FULLCONE_CLIENT_1,
        DOCKER_FULLCONE_GW_1_IP,
    ),
    (
        STUN_PROVIDER,
        ConnectionTag.DOCKER_OPEN_INTERNET_CLIENT_1,
        ConnectionTag.DOCKER_FULLCONE_CLIENT_1,
        DOCKER_FULLCONE_GW_1_IP,
    ),
    (
        STUN_PROVIDER,
        ConnectionTag.DOCKER_CONE_CLIENT_1,
        ConnectionTag.DOCKER_FULLCONE_CLIENT_1,
        DOCKER_FULLCONE_GW_1_IP,
    ),
    (
        STUN_PROVIDER,
        ConnectionTag.DOCKER_CONE_CLIENT_1,
        ConnectionTag.DOCKER_CONE_CLIENT_2,
        DOCKER_CONE_GW_2_IP,
    ),
    (
        STUN_PROVIDER,
        ConnectionTag.DOCKER_CONE_CLIENT_1,
        ConnectionTag.DOCKER_OPEN_INTERNET_CLIENT_1,
        DOCKER_OPEN_INTERNET_CLIENT_1_IP,
    ),
    (
        LOCAL_PROVIDER,
        ConnectionTag.DOCKER_OPEN_INTERNET_CLIENT_1,
        ConnectionTag.DOCKER_OPEN_INTERNET_CLIENT_2,
        DOCKER_OPEN_INTERNET_CLIENT_2_IP,
    ),
    (
        STUN_PROVIDER,
        ConnectionTag.DOCKER_OPEN_INTERNET_CLIENT_1,
        ConnectionTag.DOCKER_OPEN_INTERNET_CLIENT_2,
        DOCKER_OPEN_INTERNET_CLIENT_2_IP,
    ),
    (
        STUN_PROVIDER,
        ConnectionTag.DOCKER_SYMMETRIC_CLIENT_1,
        ConnectionTag.DOCKER_OPEN_INTERNET_CLIENT_1,
        DOCKER_OPEN_INTERNET_CLIENT_1_IP,
    ),
    (
        UPNP_PROVIDER,
        ConnectionTag.DOCKER_UPNP_CLIENT_1,
        ConnectionTag.DOCKER_UPNP_CLIENT_2,
        DOCKER_UPNP_CLIENT_2_IP,
    ),
]


@dataclass
class NodeWithMeshConnection:
    node: Node
    client: telio.Client
    conn: Connection
    conn_track: ConnectionTracker
    conn_gw: Optional[Connection]

    def _init_(self, node, client, conn, conn_track, conn_gw=None):
        self.node = node
        self.client = client
        self.conn = conn
        self.conn_track = conn_track
        self.conn_gw = conn_gw


@asynccontextmanager
async def new_connections_with_mesh_clients(
    exit_stack: AsyncExitStack,
    client1_type: ConnectionTag,
    endpoint_providers_1: List[str],
    client2_type: ConnectionTag,
    endpoint_providers_2: List[str],
    client3_type: Optional[ConnectionTag] = None,
    endpoint_providers_3: Optional[List[str]] = None,
) -> AsyncIterator[
    Tuple[
        NodeWithMeshConnection, NodeWithMeshConnection, Optional[NodeWithMeshConnection]
    ]
]:
    api = API()

    (alpha, beta, gamma) = api.default_config_three_nodes()

    (
        alpha_conn,
        alpha_conn_gw,
        alpha_conn_tracker,
    ) = await exit_stack.enter_async_context(
        new_connection_with_tracker_and_gw(
            client1_type,
            generate_connection_tracker_config(
                client1_type,
                derp_0_limits=ConnectionLimits(0, 1),
                derp_1_limits=ConnectionLimits(1, 3),
                derp_2_limits=ConnectionLimits(0, 3),
                derp_3_limits=ConnectionLimits(0, 3),
                ping_limits=ConnectionLimits(0, 5),
            ),
        )
    )

    (
        beta_conn,
        beta_conn_gw,
        beta_conn_tracker,
    ) = await exit_stack.enter_async_context(
        new_connection_with_tracker_and_gw(
            client2_type,
            generate_connection_tracker_config(
                client2_type,
                derp_0_limits=ConnectionLimits(0, 1),
                derp_1_limits=ConnectionLimits(1, 3),
                derp_2_limits=ConnectionLimits(0, 3),
                derp_3_limits=ConnectionLimits(0, 3),
                ping_limits=ConnectionLimits(0, 5),
            ),
        )
    )

    alpha_client = await exit_stack.enter_async_context(
        telio.Client(
            alpha_conn,
            alpha,
            AdapterType.BoringTun,
            telio_features=TelioFeatures(direct=Direct(providers=endpoint_providers_1)),
        ).run_meshnet(
            api.get_meshmap(alpha.id),
        )
    )

    beta_client = await exit_stack.enter_async_context(
        telio.Client(
            beta_conn,
            beta,
            AdapterType.BoringTun,
            telio_features=TelioFeatures(direct=Direct(providers=endpoint_providers_2)),
        ).run_meshnet(
            api.get_meshmap(beta.id),
        )
    )

    if client3_type and endpoint_providers_3:
        (
            gamma_conn,
            gamma_conn_gw,
            gamma_conn_tracker,
        ) = await exit_stack.enter_async_context(
            new_connection_with_tracker_and_gw(
                client3_type,
                generate_connection_tracker_config(
                    client3_type,
                    derp_0_limits=ConnectionLimits(0, 3),
                    derp_1_limits=ConnectionLimits(1, 1),
                    derp_2_limits=ConnectionLimits(0, 3),
                    derp_3_limits=ConnectionLimits(0, 3),
                ),
            )
        )

        gamma_client = await exit_stack.enter_async_context(
            telio.Client(
                gamma_conn,
                gamma,
                AdapterType.BoringTun,
                telio_features=TelioFeatures(
                    direct=Direct(providers=endpoint_providers_3)
                ),
            ).run_meshnet(
                api.get_meshmap(beta.id),
            )
        )
        gamma_conn_with_mesh = NodeWithMeshConnection(
            gamma,
            gamma_client,
            gamma_conn,
            gamma_conn_tracker,
            gamma_conn_gw,
        )
    else:
        gamma_conn_with_mesh = None

    yield (
        NodeWithMeshConnection(
            alpha, alpha_client, alpha_conn, alpha_conn_tracker, alpha_conn_gw
        ),
        NodeWithMeshConnection(
            beta, beta_client, beta_conn, beta_conn_tracker, beta_conn_gw
        ),
        gamma_conn_with_mesh,
    )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "endpoint_providers, client1_type, client2_type, _reflexive_ip",
    UHP_conn_client_types,
)
async def test_direct_working_paths(
    endpoint_providers,
    client1_type,
    client2_type,
    _reflexive_ip,
) -> None:
    async with AsyncExitStack() as exit_stack:
        (alpha, beta, _) = await exit_stack.enter_async_context(
            new_connections_with_mesh_clients(
                exit_stack,
                client1_type,
                endpoint_providers,
                client2_type,
                endpoint_providers,
            )
        )
        await testing.wait_long(
            asyncio.gather(
                alpha.client.wait_for_state_on_any_derp([State.Connected]),
                beta.client.wait_for_state_on_any_derp([State.Connected]),
            ),
        )

        await testing.wait_lengthy(
            asyncio.gather(
                alpha.client.wait_for_state_peer(
                    beta.node.public_key,
                    [State.Connected],
                    [PathType.Direct],
                ),
                beta.client.wait_for_state_peer(
                    alpha.node.public_key,
                    [State.Connected],
                    [PathType.Direct],
                ),
            ),
        )

        for server in DERP_SERVERS:
            await exit_stack.enter_async_context(
                alpha.client.get_router().break_tcp_conn_to_host(str(server["ipv4"]))
            )
            await exit_stack.enter_async_context(
                beta.client.get_router().break_tcp_conn_to_host(str(server["ipv4"]))
            )

        async with Ping(alpha.conn, beta.node.ip_addresses[0]).run() as ping:
            await testing.wait_long(ping.wait_for_next_ping())

        assert alpha.conn_track.get_out_of_limits() is None
        assert beta.conn_track.get_out_of_limits() is None


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "endpoint_providers, client1_type, client2_type",
    [
        (
            ANY_PROVIDERS,
            ConnectionTag.DOCKER_CONE_CLIENT_1,
            ConnectionTag.DOCKER_SYMMETRIC_CLIENT_1,
        ),
        (
            ANY_PROVIDERS,
            ConnectionTag.DOCKER_CONE_CLIENT_1,
            ConnectionTag.DOCKER_UDP_BLOCK_CLIENT_1,
        ),
        (
            ANY_PROVIDERS,
            ConnectionTag.DOCKER_SYMMETRIC_CLIENT_1,
            ConnectionTag.DOCKER_SYMMETRIC_CLIENT_2,
        ),
        (
            ANY_PROVIDERS,
            ConnectionTag.DOCKER_SYMMETRIC_CLIENT_1,
            ConnectionTag.DOCKER_UDP_BLOCK_CLIENT_1,
        ),
        (
            ANY_PROVIDERS,
            ConnectionTag.DOCKER_OPEN_INTERNET_CLIENT_1,
            ConnectionTag.DOCKER_UDP_BLOCK_CLIENT_1,
        ),
        (
            ANY_PROVIDERS,
            ConnectionTag.DOCKER_UDP_BLOCK_CLIENT_1,
            ConnectionTag.DOCKER_UDP_BLOCK_CLIENT_2,
        ),
        (
            LOCAL_PROVIDER,
            ConnectionTag.DOCKER_OPEN_INTERNET_CLIENT_1,
            ConnectionTag.DOCKER_FULLCONE_CLIENT_1,
        ),
        (
            LOCAL_PROVIDER,
            ConnectionTag.DOCKER_CONE_CLIENT_1,
            ConnectionTag.DOCKER_OPEN_INTERNET_CLIENT_1,
        ),
        (
            LOCAL_PROVIDER,
            ConnectionTag.DOCKER_SYMMETRIC_CLIENT_1,
            ConnectionTag.DOCKER_OPEN_INTERNET_CLIENT_1,
        ),
    ],
)
# Not sure this is needed. It will only be helpful to catch if any
# libtelio change would make any of these setup work.
async def test_direct_failing_paths(
    endpoint_providers, client1_type, client2_type
) -> None:
    async with AsyncExitStack() as exit_stack:
        (alpha, beta, _) = await exit_stack.enter_async_context(
            new_connections_with_mesh_clients(
                exit_stack,
                client1_type,
                endpoint_providers,
                client2_type,
                endpoint_providers,
            )
        )

        await testing.wait_lengthy(
            asyncio.gather(
                alpha.client.wait_for_state_on_any_derp([telio.State.Connected]),
                beta.client.wait_for_state_on_any_derp([telio.State.Connected]),
            )
        )

        await testing.wait_long(
            asyncio.gather(
                alpha.client.wait_for_state_on_any_derp([State.Connected]),
                beta.client.wait_for_state_on_any_derp([State.Connected]),
            )
        )

        with pytest.raises(asyncio.TimeoutError):
            await testing.wait_lengthy(
                asyncio.gather(
                    alpha.client.wait_for_state_peer(
                        beta.node.public_key,
                        [State.Connected],
                        [PathType.Direct],
                    ),
                    beta.client.wait_for_state_peer(
                        alpha.node.public_key,
                        [State.Connected],
                        [PathType.Direct],
                    ),
                )
            )

        for server in DERP_SERVERS:
            await exit_stack.enter_async_context(
                alpha.client.get_router().break_tcp_conn_to_host(str(server["ipv4"]))
            )
            await exit_stack.enter_async_context(
                beta.client.get_router().break_tcp_conn_to_host(str(server["ipv4"]))
            )

        await testing.wait_lengthy(
            asyncio.gather(
                alpha.client.wait_for_state_on_any_derp([State.Connecting]),
                beta.client.wait_for_state_on_any_derp([State.Connecting]),
            )
        )

        with pytest.raises(asyncio.TimeoutError):
            async with Ping(alpha.conn, beta.node.ip_addresses[0]).run() as ping:
                await testing.wait_long(ping.wait_for_next_ping())

        assert alpha.conn_track.get_out_of_limits() is None
        assert beta.conn_track.get_out_of_limits() is None


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "endpoint_providers, client1_type, client2_type, reflexive_ip",
    UHP_conn_client_types,
)
async def test_direct_short_connection_loss(
    endpoint_providers,
    client1_type,
    client2_type,
    reflexive_ip,
) -> None:
    async with AsyncExitStack() as exit_stack:
        (alpha, beta, _) = await exit_stack.enter_async_context(
            new_connections_with_mesh_clients(
                exit_stack,
                client1_type,
                endpoint_providers,
                client2_type,
                endpoint_providers,
            )
        )
        assert alpha.conn_gw and beta.conn_gw

        await testing.wait_lengthy(
            asyncio.gather(
                alpha.client.wait_for_state_on_any_derp([State.Connected]),
                beta.client.wait_for_state_on_any_derp([State.Connected]),
            )
        )

        await testing.wait_lengthy(
            asyncio.gather(
                alpha.conn_track.wait_for_event("derp_1"),
                beta.conn_track.wait_for_event("derp_1"),
            )
        )

        await testing.wait_lengthy(
            asyncio.gather(
                alpha.client.wait_for_state_peer(
                    beta.node.public_key,
                    [State.Connected],
                    [PathType.Direct],
                ),
                beta.client.wait_for_state_peer(
                    alpha.node.public_key,
                    [State.Connected],
                    [PathType.Direct],
                ),
            )
        )

        # Disrupt UHP connection
        async with AsyncExitStack() as temp_exit_stack:
            await temp_exit_stack.enter_async_context(
                alpha.client.get_router().disable_path(reflexive_ip)
            )

            # Clear conntrack to make UHP disruption faster
            await alpha.conn.create_process(["conntrack", "-F"]).execute()
            await beta.conn.create_process(["conntrack", "-F"]).execute()
            with pytest.raises(asyncio.TimeoutError):
                async with Ping(alpha.conn, beta.node.ip_addresses[0]).run() as ping:
                    await testing.wait_long(ping.wait_for_next_ping())

        async with Ping(alpha.conn, beta.node.ip_addresses[0]).run() as ping:
            await testing.wait_lengthy(ping.wait_for_next_ping())

        assert alpha.conn_track.get_out_of_limits() is None
        assert beta.conn_track.get_out_of_limits() is None


@pytest.mark.asyncio
@pytest.mark.long
@pytest.mark.parametrize(
    "endpoint_providers, client1_type, client2_type, reflexive_ip",
    UHP_conn_client_types,
)
async def test_direct_connection_loss_for_infinity(
    endpoint_providers,
    client1_type,
    client2_type,
    reflexive_ip,
) -> None:
    async with AsyncExitStack() as exit_stack:
        (alpha, beta, _) = await exit_stack.enter_async_context(
            new_connections_with_mesh_clients(
                exit_stack,
                client1_type,
                endpoint_providers,
                client2_type,
                endpoint_providers,
            )
        )
        assert alpha.conn_gw and beta.conn_gw

        await testing.wait_lengthy(
            asyncio.gather(
                alpha.client.wait_for_state_on_any_derp([telio.State.Connected]),
                beta.client.wait_for_state_on_any_derp([telio.State.Connected]),
            )
        )

        await testing.wait_lengthy(
            asyncio.gather(
                alpha.conn_track.wait_for_event("derp_1"),
                beta.conn_track.wait_for_event("derp_1"),
            )
        )

        await testing.wait_lengthy(
            asyncio.gather(
                alpha.client.wait_for_state_peer(
                    beta.node.public_key,
                    [State.Connected],
                    [PathType.Direct],
                ),
                beta.client.wait_for_state_peer(
                    alpha.node.public_key,
                    [State.Connected],
                    [PathType.Direct],
                ),
            )
        )

        # Break UHP route and wait for relay connection
        async with AsyncExitStack() as temp_exit_stack:
            await temp_exit_stack.enter_async_context(
                alpha.client.get_router().disable_path(reflexive_ip)
            )
            with pytest.raises(asyncio.TimeoutError):
                async with Ping(alpha.conn, beta.node.ip_addresses[0]).run() as ping:
                    await testing.wait_short(ping.wait_for_next_ping())

            await testing.wait_lengthy(
                asyncio.gather(
                    alpha.client.wait_for_state_peer(
                        beta.node.public_key, [State.Connected]
                    ),
                    beta.client.wait_for_state_peer(
                        alpha.node.public_key, [State.Connected]
                    ),
                ),
            )

            async with Ping(alpha.conn, beta.node.ip_addresses[0]).run() as ping:
                await testing.wait_lengthy(ping.wait_for_next_ping())

        assert alpha.conn_track.get_out_of_limits() is None
        assert beta.conn_track.get_out_of_limits() is None


@pytest.mark.timeout(90)
@pytest.mark.asyncio
@pytest.mark.parametrize(
    "alpha_connection_tag, beta_connection_tag, ep1, ep2",
    [
        pytest.param(
            ConnectionTag.DOCKER_CONE_CLIENT_1,
            ConnectionTag.DOCKER_CONE_CLIENT_2,
            "stun",
            "stun",
        ),
        pytest.param(
            ConnectionTag.DOCKER_UPNP_CLIENT_1,
            ConnectionTag.DOCKER_UPNP_CLIENT_2,
            "upnp",
            "upnp",
        ),
        pytest.param(
            ConnectionTag.DOCKER_UPNP_CLIENT_1,
            ConnectionTag.DOCKER_CONE_CLIENT_2,
            "upnp",
            "stun",
        ),
        pytest.param(
            ConnectionTag.DOCKER_UPNP_CLIENT_1,
            ConnectionTag.DOCKER_OPEN_INTERNET_CLIENT_1,
            "upnp",
            "local",
        ),
        pytest.param(
            ConnectionTag.DOCKER_CONE_CLIENT_1,
            ConnectionTag.DOCKER_OPEN_INTERNET_CLIENT_1,
            "stun",
            "local",
        ),
    ],
)
async def test_direct_connection_endpoint_gone(
    alpha_connection_tag: ConnectionTag,
    beta_connection_tag: ConnectionTag,
    ep1: str,
    ep2: str,
) -> None:
    async with AsyncExitStack() as exit_stack:
        (alpha, beta, _) = await exit_stack.enter_async_context(
            new_connections_with_mesh_clients(
                exit_stack, alpha_connection_tag, [ep1], beta_connection_tag, [ep2]
            )
        )
        assert alpha.conn_gw and beta.conn_gw

        async def _check_if_true_direct_connection() -> None:
            async with AsyncExitStack() as temp_exit_stack:
                for derp in DERP_SERVERS:
                    await temp_exit_stack.enter_async_context(
                        alpha.client.get_router().break_tcp_conn_to_host(
                            str(derp["ipv4"])
                        )
                    )
                    await temp_exit_stack.enter_async_context(
                        beta.client.get_router().break_tcp_conn_to_host(
                            str(derp["ipv4"])
                        )
                    )

                await testing.wait_lengthy(
                    asyncio.gather(
                        alpha.client.wait_for_state_on_any_derp(
                            [State.Connecting, State.Disconnected],
                        ),
                        beta.client.wait_for_state_on_any_derp(
                            [State.Connecting, State.Disconnected],
                        ),
                    ),
                )

                async with Ping(alpha.conn, beta.node.ip_addresses[0]).run() as ping:
                    await testing.wait_lengthy(ping.wait_for_next_ping())

        await testing.wait_lengthy(
            asyncio.gather(
                alpha.client.wait_for_state_on_any_derp([State.Connected]),
                beta.client.wait_for_state_on_any_derp([State.Connected]),
            ),
        )

        await testing.wait_long(
            asyncio.gather(
                alpha.conn_track.wait_for_event("derp_1"),
                beta.conn_track.wait_for_event("derp_1"),
            )
        )

        await testing.wait_lengthy(
            asyncio.gather(
                alpha.client.wait_for_state_peer(
                    beta.node.public_key,
                    [State.Connected],
                    [PathType.Direct],
                ),
                beta.client.wait_for_state_peer(
                    alpha.node.public_key,
                    [State.Connected],
                    [PathType.Direct],
                ),
            ),
        )

        await _check_if_true_direct_connection()

        await testing.wait_lengthy(
            asyncio.gather(
                alpha.client.wait_for_state_on_any_derp(
                    [State.Connected],
                ),
                beta.client.wait_for_state_on_any_derp(
                    [State.Connected],
                ),
            ),
        )

        async with AsyncExitStack() as temp_exit_stack:
            await temp_exit_stack.enter_async_context(
                alpha.client.get_router().disable_path(
                    alpha.client.get_endpoint_address(beta.node.public_key)
                )
            )
            await temp_exit_stack.enter_async_context(
                beta.client.get_router().disable_path(
                    beta.client.get_endpoint_address(alpha.node.public_key)
                )
            )

            await testing.wait_lengthy(
                asyncio.gather(
                    alpha.client.wait_for_state_peer(
                        beta.node.public_key, [State.Connected]
                    ),
                    beta.client.wait_for_state_peer(
                        alpha.node.public_key, [State.Connected]
                    ),
                ),
            )

            async with Ping(alpha.conn, beta.node.ip_addresses[0]).run() as ping:
                await testing.wait_lengthy(ping.wait_for_next_ping())

        await testing.wait_lengthy(
            asyncio.gather(
                alpha.client.wait_for_state_peer(
                    beta.node.public_key,
                    [State.Connected],
                    [PathType.Direct],
                ),
                beta.client.wait_for_state_peer(
                    alpha.node.public_key,
                    [State.Connected],
                    [PathType.Direct],
                ),
            ),
        )
        await _check_if_true_direct_connection()

        assert alpha.conn_track.get_out_of_limits() is None
        assert beta.conn_track.get_out_of_limits() is None
