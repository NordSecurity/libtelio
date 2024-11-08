import asyncio
import pytest
from contextlib import AsyncExitStack
from helpers import SetupParameters, setup_mesh_nodes
from telio import AdapterType, LinkState
from telio_features import TelioFeatures, LinkDetection, Wireguard, PersistentKeepalive
from typing import List, Tuple
from utils.connection import Connection
from utils.connection_util import ConnectionTag
from utils.ping import ping


def long_persistent_keepalive_periods() -> Wireguard:
    return Wireguard(
        persistent_keepalive=PersistentKeepalive(
            proxying=3600, direct=3600, vpn=3600, stun=3600
        )
    )


def _generate_setup_paramete_pair(
    cfg: List[Tuple[ConnectionTag, AdapterType]],
    enhaced_detection: bool,
) -> List[SetupParameters]:
    if enhaced_detection:
        count = 1
    else:
        count = 0

    return [
        SetupParameters(
            connection_tag=tag,
            adapter_type=adapter,
            features=TelioFeatures(
                link_detection=LinkDetection(rtt_seconds=1, no_of_pings=count),
                wireguard=long_persistent_keepalive_periods(),
            ),
        )
        for tag, adapter in cfg
    ]


FEATURE_ENABLED_PARAMS = [
    # This scenario has been removed because it was causing flakyness due to LLT-5014.
    # Add it back when the issue is fixed.
    # pytest.param(
    #     _generate_setup_paramete_pair([
    #         (ConnectionTag.DOCKER_CONE_CLIENT_1, AdapterType.LinuxNativeWg),
    #         (ConnectionTag.DOCKER_CONE_CLIENT_2, AdapterType.LinuxNativeWg),
    #     ])
    # ),
    pytest.param(
        _generate_setup_paramete_pair(
            [
                (ConnectionTag.DOCKER_CONE_CLIENT_1, AdapterType.LinuxNativeWg),
                (ConnectionTag.DOCKER_CONE_CLIENT_2, AdapterType.BoringTun),
            ],
            False,
        )
    ),
    pytest.param(
        _generate_setup_paramete_pair(
            [
                (ConnectionTag.DOCKER_CONE_CLIENT_1, AdapterType.LinuxNativeWg),
                (ConnectionTag.DOCKER_CONE_CLIENT_2, AdapterType.BoringTun),
            ],
            True,
        )
    ),
    pytest.param(
        _generate_setup_paramete_pair(
            [
                (ConnectionTag.DOCKER_CONE_CLIENT_1, AdapterType.BoringTun),
                (ConnectionTag.DOCKER_CONE_CLIENT_2, AdapterType.BoringTun),
            ],
            False,
        )
    ),
    pytest.param(
        _generate_setup_paramete_pair(
            [
                (ConnectionTag.DOCKER_CONE_CLIENT_1, AdapterType.BoringTun),
                (ConnectionTag.DOCKER_CONE_CLIENT_2, AdapterType.BoringTun),
            ],
            True,
        )
    ),
    pytest.param(
        _generate_setup_paramete_pair(
            [
                (ConnectionTag.WINDOWS_VM_1, AdapterType.WindowsNativeWg),
                (ConnectionTag.DOCKER_CONE_CLIENT_1, AdapterType.BoringTun),
            ],
            False,
        ),
        marks=pytest.mark.windows,
    ),
    pytest.param(
        _generate_setup_paramete_pair(
            [
                (ConnectionTag.WINDOWS_VM_1, AdapterType.WindowsNativeWg),
                (ConnectionTag.DOCKER_CONE_CLIENT_1, AdapterType.BoringTun),
            ],
            True,
        ),
        marks=pytest.mark.windows,
    ),
]

FEATURE_DISABLED_PARAMS = [
    pytest.param([
        SetupParameters(
            connection_tag=ConnectionTag.DOCKER_CONE_CLIENT_1,
            adapter_type=AdapterType.BoringTun,
        ),
        SetupParameters(
            connection_tag=ConnectionTag.DOCKER_CONE_CLIENT_2,
            adapter_type=AdapterType.BoringTun,
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

        # 1 down event when Connecting, 1 up event when Connected
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
            await ping(connection_alpha, beta.ip_addresses[0])
            await ping(connection_beta, alpha.ip_addresses[0])

        # Expect no nolink event while peers are active
        alpha_events = client_beta.get_link_state_events(alpha.public_key)
        beta_events = client_alpha.get_link_state_events(beta.public_key)

        # 1 down event when Connecting, 1 up event when Connected
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

        await ping(connection_alpha, beta.ip_addresses[0])
        await ping(connection_beta, alpha.ip_addresses[0])

        # Expect no link event while peers are idle
        await asyncio.sleep(20)

        await ping(connection_alpha, beta.ip_addresses[0])
        await ping(connection_beta, alpha.ip_addresses[0])

        alpha_events = client_beta.get_link_state_events(alpha.public_key)
        beta_events = client_alpha.get_link_state_events(beta.public_key)

        # 1 down event when Connecting, 1 up event when Connected
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

        await ping(connection_alpha, beta.ip_addresses[0])
        await ping(connection_beta, alpha.ip_addresses[0])

        await client_beta.stop_device()

        await asyncio.sleep(1)

        with pytest.raises(asyncio.TimeoutError):
            await ping(connection_alpha, beta.ip_addresses[0], 5)

        await asyncio.sleep(25)
        alpha_events = client_beta.get_link_state_events(alpha.public_key)
        beta_events = client_alpha.get_link_state_events(beta.public_key)

        # 1 down event when Connecting, 1 up event when Connected
        assert alpha_events == [LinkState.Down, LinkState.Up]
        # 1 down event when Connecting, 1 up event when Connected, 1 down event when client is stopped
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

        await ping(connection_alpha, beta.ip_addresses[0])
        await ping(connection_beta, alpha.ip_addresses[0])

        await asyncio.sleep(30)

        alpha_events = client_beta.get_link_state_events(alpha.public_key)
        beta_events = client_alpha.get_link_state_events(beta.public_key)

        assert len(alpha_events) > 1
        assert len(beta_events) > 1
        assert all(e is None for e in alpha_events)
        assert all(e is None for e in beta_events)


class ICMP_control:
    def __init__(self, conn: Connection):
        self._conn = conn

    async def __aenter__(self):
        proc = self._conn.create_process([
            "iptables",
            "-I",
            "INPUT",
            "-p",
            "icmp",
            "--icmp-type",
            "echo-request",
            "-j",
            "DROP",
        ])
        await proc.execute()

    async def __aexit__(self, _exc_t, exc_v, exc_tb):
        proc = self._conn.create_process([
            "iptables",
            "-D",
            "INPUT",
            "-p",
            "icmp",
            "--icmp-type",
            "echo-request",
            "-j",
            "DROP",
        ])
        await proc.execute()


@pytest.mark.asyncio
@pytest.mark.parametrize("setup_params", FEATURE_ENABLED_PARAMS)
async def test_event_link_state_peer_doesnt_respond(
    setup_params: List[SetupParameters],
) -> None:
    # Peer is online, however doesn't respond to ICMP ECHO REQUESTS.
    # This means that link detection must not consider the peer offline since it will sent WG-PASSIVE_KEEPALIVE back and this test assures that.
    async with AsyncExitStack() as exit_stack:
        env = await setup_mesh_nodes(exit_stack, setup_params)
        alpha, beta = env.nodes
        client_alpha, client_beta = env.clients
        connection_alpha, connection_beta = [
            conn.connection for conn in env.connections
        ]

        async with ICMP_control(connection_beta):
            with pytest.raises(asyncio.TimeoutError):
                await ping(connection_alpha, beta.ip_addresses[0], 8)

            alpha_events = client_beta.get_link_state_events(alpha.public_key)
            beta_events = client_alpha.get_link_state_events(beta.public_key)

            # The connection is normal and events should be: initial down, then several up events but no more down events
            assert alpha_events.count(LinkState.Down) == 1
            assert beta_events.count(LinkState.Down) == 1

            # wait enough to pass 10 second mark since our ping request, which should trigger passive-keepalive by wireguard
            await asyncio.sleep(5)

            alpha_events = client_beta.get_link_state_events(alpha.public_key)
            beta_events = client_alpha.get_link_state_events(beta.public_key)

            # there should be no additional link down event

            assert alpha_events.count(LinkState.Down) == 1
            assert beta_events.count(LinkState.Down) == 1
