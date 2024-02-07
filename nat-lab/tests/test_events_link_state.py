import asyncio
import pytest
from contextlib import AsyncExitStack
from helpers import SetupParameters, setup_mesh_nodes
from telio import AdapterType, LinkState
from telio_features import TelioFeatures, LinkDetection, Wireguard
from typing import List, Tuple
from utils import testing
from utils.connection_util import ConnectionTag
from utils.ping import Ping


def long_persistent_keepalive_periods() -> Wireguard:
    return Wireguard(proxying=3600, direct=3600, vpn=3600, stun=3600)


def _generate_setup_paramete_pair(
    cfg: List[Tuple[ConnectionTag, AdapterType]],
) -> List[SetupParameters]:
    return [
        SetupParameters(
            connection_tag=tag,
            adapter_type=adapter,
            features=TelioFeatures(
                link_detection=LinkDetection(rtt_seconds=1),
                wireguard=long_persistent_keepalive_periods(),
            ),
        )
        for tag, adapter in cfg
    ]


FEATURE_ENABLED_PARAMS = [
    pytest.param(
        _generate_setup_paramete_pair([
            (ConnectionTag.DOCKER_CONE_CLIENT_1, AdapterType.LinuxNativeWg),
            (ConnectionTag.DOCKER_CONE_CLIENT_2, AdapterType.LinuxNativeWg),
        ])
    ),
    pytest.param(
        _generate_setup_paramete_pair([
            (ConnectionTag.DOCKER_CONE_CLIENT_1, AdapterType.LinuxNativeWg),
            (ConnectionTag.DOCKER_CONE_CLIENT_2, AdapterType.BoringTun),
        ])
    ),
    pytest.param(
        _generate_setup_paramete_pair([
            (ConnectionTag.DOCKER_CONE_CLIENT_1, AdapterType.BoringTun),
            (ConnectionTag.DOCKER_CONE_CLIENT_2, AdapterType.BoringTun),
        ])
    ),
]

FEATURE_DISABLED_PARAMS = [
    pytest.param([
        SetupParameters(
            connection_tag=ConnectionTag.DOCKER_CONE_CLIENT_1,
            adapter_type=AdapterType.LinuxNativeWg,
        ),
        SetupParameters(
            connection_tag=ConnectionTag.DOCKER_CONE_CLIENT_2,
            adapter_type=AdapterType.LinuxNativeWg,
        ),
    ])
]


@pytest.mark.asyncio
@pytest.mark.parametrize("setup_params", FEATURE_ENABLED_PARAMS)
async def test_event_link_state_peers_idle_all_time(
    setup_params: List[SetupParameters],
) -> None:
    async with AsyncExitStack() as exit_stack:
        env = await setup_mesh_nodes(exit_stack, setup_params)
        alpha, beta = env.nodes
        client_alpha, client_beta = env.clients

        # Expect no link event while peers are idle
        await asyncio.sleep(20)
        alpha_events = client_beta.get_link_state_events(alpha.public_key)
        beta_events = client_alpha.get_link_state_events(beta.public_key)

        # 1 down when node is Connecting and 1 up when node is Connected
        assert alpha_events == [LinkState.Down, LinkState.Up]
        assert beta_events == [LinkState.Down, LinkState.Up]


@pytest.mark.asyncio
@pytest.mark.parametrize("setup_params", FEATURE_ENABLED_PARAMS)
async def test_event_link_state_peers_exchanging_data_for_a_long_time(
    setup_params: List[SetupParameters],
) -> None:
    async with AsyncExitStack() as exit_stack:
        env = await setup_mesh_nodes(exit_stack, setup_params)
        alpha, beta = env.nodes
        client_alpha, client_beta = env.clients
        connection_alpha, connection_beta = [
            conn.connection for conn in env.connections
        ]

        for _ in range(0, 40):
            await asyncio.sleep(1)
            async with Ping(connection_alpha, beta.ip_addresses[0]).run() as ping:
                await testing.wait_long(ping.wait_for_next_ping())
            async with Ping(connection_beta, alpha.ip_addresses[0]).run() as ping:
                await testing.wait_long(ping.wait_for_next_ping())

        # Expect no nolink event while peers are active
        alpha_events = client_beta.get_link_state_events(alpha.public_key)
        beta_events = client_alpha.get_link_state_events(beta.public_key)

        # 1 down when node is Connecting and 1 up when node is Connected
        assert alpha_events == [LinkState.Down, LinkState.Up]
        assert beta_events == [LinkState.Down, LinkState.Up]


@pytest.mark.asyncio
@pytest.mark.parametrize("setup_params", FEATURE_ENABLED_PARAMS)
async def test_event_link_state_peers_exchanging_data_then_idling_then_resume(
    setup_params: List[SetupParameters],
) -> None:
    async with AsyncExitStack() as exit_stack:
        env = await setup_mesh_nodes(exit_stack, setup_params)
        alpha, beta = env.nodes
        client_alpha, client_beta = env.clients
        connection_alpha, connection_beta = [
            conn.connection for conn in env.connections
        ]

        async with Ping(connection_alpha, beta.ip_addresses[0]).run() as ping:
            await testing.wait_long(ping.wait_for_next_ping())
        async with Ping(connection_beta, alpha.ip_addresses[0]).run() as ping:
            await testing.wait_long(ping.wait_for_next_ping())

        # Expect no link event while peers are idle
        await asyncio.sleep(20)

        async with Ping(connection_alpha, beta.ip_addresses[0]).run() as ping:
            await testing.wait_long(ping.wait_for_next_ping())
        async with Ping(connection_beta, alpha.ip_addresses[0]).run() as ping:
            await testing.wait_long(ping.wait_for_next_ping())

        alpha_events = client_beta.get_link_state_events(alpha.public_key)
        beta_events = client_alpha.get_link_state_events(beta.public_key)

        # 1 down when node is Connecting and 1 up when node is Connected
        assert alpha_events == [LinkState.Down, LinkState.Up]
        assert beta_events == [LinkState.Down, LinkState.Up]


@pytest.mark.asyncio
@pytest.mark.parametrize("setup_params", FEATURE_ENABLED_PARAMS)
async def test_event_link_state_peer_goes_offline(
    setup_params: List[SetupParameters],
) -> None:
    async with AsyncExitStack() as exit_stack:
        env = await setup_mesh_nodes(exit_stack, setup_params)
        alpha, beta = env.nodes
        client_alpha, client_beta = env.clients
        connection_alpha, connection_beta = [
            conn.connection for conn in env.connections
        ]

        async with Ping(connection_alpha, beta.ip_addresses[0]).run() as ping:
            await testing.wait_long(ping.wait_for_next_ping())
        async with Ping(connection_beta, alpha.ip_addresses[0]).run() as ping:
            await testing.wait_long(ping.wait_for_next_ping())

        await client_beta.stop_device()

        await asyncio.sleep(1)

        with pytest.raises(asyncio.TimeoutError):
            async with Ping(connection_alpha, beta.ip_addresses[0]).run() as ping:
                await testing.wait_normal(ping.wait_for_next_ping())

        await asyncio.sleep(15)
        alpha_events = client_beta.get_link_state_events(alpha.public_key)
        beta_events = client_alpha.get_link_state_events(beta.public_key)

        # 1 down when node is Connecting and 1 up when node is Connected
        assert alpha_events == [LinkState.Down, LinkState.Up]
        # beta will have 2 down events: 1 when is Connecting and 1 detected
        assert beta_events == [LinkState.Down, LinkState.Up, LinkState.Down]


@pytest.mark.asyncio
@pytest.mark.parametrize("setup_params", FEATURE_DISABLED_PARAMS)
async def test_event_link_state_feature_disabled(
    setup_params: List[SetupParameters],
) -> None:
    async with AsyncExitStack() as exit_stack:
        env = await setup_mesh_nodes(exit_stack, setup_params)
        alpha, beta = env.nodes
        client_alpha, client_beta = env.clients
        connection_alpha, connection_beta = [
            conn.connection for conn in env.connections
        ]

        async with Ping(connection_alpha, beta.ip_addresses[0]).run() as ping:
            await testing.wait_long(ping.wait_for_next_ping())
        async with Ping(connection_beta, alpha.ip_addresses[0]).run() as ping:
            await testing.wait_long(ping.wait_for_next_ping())

        await asyncio.sleep(30)

        alpha_events = client_beta.get_link_state_events(alpha.public_key)
        beta_events = client_alpha.get_link_state_events(beta.public_key)

        # There should be 2 node events Connecting and Connected
        # Both of them should have link_state field empty
        assert alpha_events == [None, None]
        assert beta_events == [None, None]
