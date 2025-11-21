import asyncio
import pytest
from contextlib import AsyncExitStack
from helpers import SetupParameters, setup_mesh_nodes
from typing import List, Tuple
from utils.bindings import (
    default_features,
    FeatureLinkDetection,
    FeatureWireguard,
    FeaturePersistentKeepalive,
    FeaturePolling,
    LinkState,
    TelioAdapterType,
)
from utils.connection import Connection, ConnectionTag
from utils.ping import ping

RTT_SECONDS = 1
PING_TIMEOUT = 3
# The interval at which link-state events are emitted.
# Determined by WG-PASSIVE_KEEPALIVE + RTT delay
LINK_STATE_INTERVAL = 10 + RTT_SECONDS
# The time by which we otherwise would expect to emit at least one link-state event.
IDLE_TIMEOUT = 2 * LINK_STATE_INTERVAL


def long_persistent_keepalive_periods() -> FeatureWireguard:
    return FeatureWireguard(
        persistent_keepalive=FeaturePersistentKeepalive(
            proxying=3600, direct=3600, vpn=3600, stun=3600
        ),
        polling=FeaturePolling(
            wireguard_polling_period=1000,
            wireguard_polling_period_after_state_change=50,
        ),
        enable_dynamic_wg_nt_control=False,
        skt_buffer_size=None,
        inter_thread_channel_size=None,
        max_inter_thread_batched_pkts=None,
    )


def _generate_setup_parameter_pair(
    cfg: List[Tuple[ConnectionTag, TelioAdapterType]],
    enhaced_detection: bool,
) -> List[SetupParameters]:
    if enhaced_detection:
        count = 1
    else:
        count = 0

    features = default_features(enable_link_detection=True)
    features.link_detection = FeatureLinkDetection(
        rtt_seconds=RTT_SECONDS, no_of_pings=count, use_for_downgrade=False
    )
    features.wireguard = long_persistent_keepalive_periods()

    return [
        SetupParameters(
            connection_tag=tag,
            adapter_type_override=adapter,
            features=features,
        )
        for tag, adapter in cfg
    ]


FEATURE_ENABLED_PARAMS = [
    # This scenario has been removed because it was causing flakyness due to LLT-5014.
    # Add it back when the issue is fixed.
    # pytest.param(
    #     _generate_setup_parameter_pair([
    #         (ConnectionTag.DOCKER_CONE_CLIENT_1, TelioAdapterType.LINUX_NATIVE_TUN),
    #         (ConnectionTag.DOCKER_CONE_CLIENT_2, TelioAdapterType.LINUX_NATIVE_TUN),
    #     ])
    # ),
    pytest.param(
        _generate_setup_parameter_pair(
            [
                (ConnectionTag.DOCKER_CONE_CLIENT_1, TelioAdapterType.LINUX_NATIVE_TUN),
                (ConnectionTag.DOCKER_CONE_CLIENT_2, TelioAdapterType.NEP_TUN),
            ],
            False,
        )
    ),
    pytest.param(
        _generate_setup_parameter_pair(
            [
                (ConnectionTag.sdsd, TelioAdapterType.LINUX_NATIVE_TUN),
                (ConnectionTag.DOCKER_CONE_CLIENT_2, TelioAdapterType.NEP_TUN),
            ],
            True,
        )
    ),
    pytest.param(
        _generate_setup_parameter_pair(
            [
                (ConnectionTag.DOCKER_CONE_CLIENT_1, TelioAdapterType.NEP_TUN),
                (ConnectionTag.DOCKER_CONE_CLIENT_2, TelioAdapterType.NEP_TUN),
            ],
            False,
        )
    ),
    pytest.param(
        _generate_setup_parameter_pair(
            [
                (ConnectionTag.DOCKER_CONE_CLIENT_1, TelioAdapterType.NEP_TUN),
                (ConnectionTag.DOCKER_CONE_CLIENT_2, TelioAdapterType.NEP_TUN),
            ],
            True,
        )
    ),
    pytest.param(
        _generate_setup_parameter_pair(
            [
                (ConnectionTag.VM_WINDOWS_1, TelioAdapterType.WINDOWS_NATIVE_TUN),
                (ConnectionTag.DOCKER_CONE_CLIENT_1, TelioAdapterType.NEP_TUN),
            ],
            False,
        ),
        marks=pytest.mark.windows,
    ),
    pytest.param(
        _generate_setup_parameter_pair(
            [
                (ConnectionTag.VM_WINDOWS_1, TelioAdapterType.WINDOWS_NATIVE_TUN),
                (ConnectionTag.DOCKER_CONE_CLIENT_1, TelioAdapterType.NEP_TUN),
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
            adapter_type_override=TelioAdapterType.NEP_TUN,
        ),
        SetupParameters(
            connection_tag=ConnectionTag.DOCKER_CONE_CLIENT_2,
            adapter_type_override=TelioAdapterType.NEP_TUN,
        ),
    ])
]


async def wait_for_any_with_timeout(tasks, timeout: float):
    done_tasks, _pending_tasks = await asyncio.wait(
        tasks,
        timeout=timeout,
        return_when=asyncio.FIRST_COMPLETED,
    )
    if len(done_tasks) == 0:
        raise asyncio.TimeoutError


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
        with pytest.raises(asyncio.TimeoutError):
            await wait_for_any_with_timeout(
                [
                    asyncio.create_task(
                        client_alpha.wait_for_link_state(
                            beta.public_key, LinkState.DOWN
                        )
                    ),
                    asyncio.create_task(
                        client_beta.wait_for_link_state(
                            alpha.public_key, LinkState.DOWN
                        )
                    ),
                ],
                timeout=IDLE_TIMEOUT,
            )


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

        for _ in range(0, 25):
            await asyncio.sleep(1)
            await ping(connection_alpha, beta.ip_addresses[0])
            await ping(connection_beta, alpha.ip_addresses[0])

        assert client_alpha.get_link_state_events(beta.public_key) == [
            LinkState.DOWN,
            LinkState.UP,
        ]
        assert client_beta.get_link_state_events(alpha.public_key) == [
            LinkState.DOWN,
            LinkState.UP,
        ]


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
        with pytest.raises(asyncio.TimeoutError):
            await wait_for_any_with_timeout(
                [
                    asyncio.create_task(
                        client_alpha.wait_for_link_state(
                            beta.public_key, LinkState.DOWN
                        )
                    ),
                    asyncio.create_task(
                        client_beta.wait_for_link_state(
                            alpha.public_key, LinkState.DOWN
                        )
                    ),
                ],
                timeout=IDLE_TIMEOUT,
            )

        await ping(connection_alpha, beta.ip_addresses[0])
        await ping(connection_beta, alpha.ip_addresses[0])

        # Wait for another 5 seconds
        with pytest.raises(asyncio.TimeoutError):
            await wait_for_any_with_timeout(
                [
                    asyncio.create_task(
                        client_alpha.wait_for_link_state(
                            beta.public_key, LinkState.DOWN
                        )
                    ),
                    asyncio.create_task(
                        client_beta.wait_for_link_state(
                            alpha.public_key, LinkState.DOWN
                        )
                    ),
                ],
                timeout=5,
            )

        # Expect the links are still UP
        assert client_alpha.get_link_state_events(beta.public_key) == [
            LinkState.DOWN,
            LinkState.UP,
        ]
        assert client_beta.get_link_state_events(alpha.public_key) == [
            LinkState.DOWN,
            LinkState.UP,
        ]


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

        await ping(connection_beta, alpha.ip_addresses[0])
        # Sending ping from alpha to beta ensures that the WireGuard's internal timer for Keepalive-Timeout (10s) is
        # reset. This is because the ICMP Reply message that is sent from the beta to alpha, is the last packet and
        # it's an incomming packet from the point of view of alpha. Which means that the stop_device below can take
        # any amount of time without triggering passive keepalive timeout. The WireGuard's internal timer will be
        # restarted by the ping sent in the gather section further down below.
        await ping(connection_alpha, beta.ip_addresses[0])

        await client_beta.stop_device()

        # Expect the link to still be UP for the fist 10 + RTT seconds
        results = await asyncio.gather(
            ping(connection_alpha, beta.ip_addresses[0], PING_TIMEOUT),
            client_alpha.wait_for_link_state(
                beta.public_key, LinkState.DOWN, LINK_STATE_INTERVAL
            ),
            return_exceptions=True,
        )

        for idx, result in enumerate(results):
            if not isinstance(result, asyncio.TimeoutError):
                raise AssertionError(f"{idx}: Expected to timeout but got {result}")

        # Expect the link down event
        # It should arrive in 11-15 seconds after the link is cut and enhanced detection disabled
        # And 22-25 seconds if the enhanced detection is enabled
        await client_alpha.wait_for_link_state(beta.public_key, LinkState.DOWN)
        assert client_alpha.get_link_state_events(beta.public_key) == [
            LinkState.DOWN,
            LinkState.UP,
            LinkState.DOWN,
        ]
        # Although the beta device has been stopped, it should still see alpha as up
        assert client_beta.get_link_state_events(alpha.public_key) == [
            LinkState.DOWN,
            LinkState.UP,
        ]


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

        assert len(alpha_events) == 0
        assert len(beta_events) == 0


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

    async def __aexit__(self, *_):
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
                await ping(connection_alpha, beta.ip_addresses[0], PING_TIMEOUT)

            # Wait enough to pass 10 second mark since our ping request, which should trigger passive-keepalive by wireguard
            # + rtt delay for enhanced detection mode
            with pytest.raises(asyncio.TimeoutError):
                await wait_for_any_with_timeout(
                    [
                        asyncio.create_task(
                            client_alpha.wait_for_link_state(
                                beta.public_key, LinkState.DOWN
                            )
                        ),
                        asyncio.create_task(
                            client_beta.wait_for_link_state(
                                alpha.public_key, LinkState.DOWN
                            )
                        ),
                    ],
                    timeout=IDLE_TIMEOUT,
                )
