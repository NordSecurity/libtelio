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
from utils.connection_util import add_outgoing_packets_delay
from utils.ping import ping

WG_POLLING_PERIOD_S = 1
WG_PASSIVE_KEEPALIVE_S = 10
MAX_RTT_ALLOWED_S = 1
# The duration which after a link is considered not to be up. (ie: PossibleDown->Down)
LINK_STATE_TIMEOUT_S = WG_PASSIVE_KEEPALIVE_S + MAX_RTT_ALLOWED_S
POSSIBLE_DOWN_DELAY = 3
# Enhanced detection (ED) issues a ping when there's the Up->PossibleDown link state transition,
# if no ICMP reply is received for LINK_STATE_TIMEOUT_S the link state will transit to Down.
POSSIBLE_DOWN_DELAY_ED = LINK_STATE_TIMEOUT_S
# The time by which we would expect to emit at least one link-state event, when tx_ts > rx_ts and none rx packet for the same period.
TOLERANCE = 1.5
IDLE_TIMEOUT_S = round((LINK_STATE_TIMEOUT_S + POSSIBLE_DOWN_DELAY) * TOLERANCE)
IDLE_TIMEOUT_ED_S = round((LINK_STATE_TIMEOUT_S + POSSIBLE_DOWN_DELAY_ED) * TOLERANCE)


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
        rtt_seconds=MAX_RTT_ALLOWED_S, no_of_pings=count, use_for_downgrade=False
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
                (ConnectionTag.DOCKER_CONE_CLIENT_1, TelioAdapterType.LINUX_NATIVE_TUN),
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


def resolve_idle_timeout(params: SetupParameters) -> int:
    assert params.features.link_detection
    if params.features.link_detection.no_of_pings > 0:
        return IDLE_TIMEOUT_ED_S
    return IDLE_TIMEOUT_S


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
                timeout=resolve_idle_timeout(setup_params[0]),
            )

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
                timeout=resolve_idle_timeout(setup_params[0]),
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
                timeout=resolve_idle_timeout(setup_params[0]),
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
        # Stopping beta generates rx/tx traffic with alpha, so wait 1 second before the next ping to skip the current
        # polling interval and therefore guarantee that only tx increases
        await asyncio.sleep(WG_POLLING_PERIOD_S)

        # Expect the link to still be UP for the duration of WG Keepalive timeout + Max. RTT Allowed
        with pytest.raises(asyncio.TimeoutError):
            await ping(connection_alpha, beta.ip_addresses[0], MAX_RTT_ALLOWED_S)
        with pytest.raises(asyncio.TimeoutError):
            await client_alpha.wait_for_link_state(
                beta.public_key, LinkState.DOWN, WG_PASSIVE_KEEPALIVE_S
            )

        # DOWN link state is expected after we send a packet and don't receive for more than:
        # WG Keep alive + Max. RTT allowed + Delay, where,
        #      Delay = 3s when Enhanced detection is disabled
        #      Delay = (WG Keep alive + Max. RTT allowed) when Enhanced detection is enabled
        await client_alpha.wait_for_link_state(
            beta.public_key,
            LinkState.DOWN,
            (resolve_idle_timeout(setup_params[0]) - WG_PASSIVE_KEEPALIVE_S),
        )

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

        await asyncio.sleep(IDLE_TIMEOUT_ED_S)

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

        # After this ping beta will have ts_tx > ts_rx (ICMP reply)
        await ping(connection_alpha, beta.ip_addresses[0])

        async with ICMP_control(connection_beta):
            with pytest.raises(asyncio.TimeoutError):
                await ping(connection_alpha, beta.ip_addresses[0], WG_POLLING_PERIOD_S)

            # If there was no connection, DOWN link state should be detected after 14-21s (ie: IDLE_TIMEOUT_S),
            # however beta is sending a keepalive after WG_PASSIVE_KEEPALIVE_S to let alpha knows that he's alive.
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
                    timeout=resolve_idle_timeout(setup_params[0]),
                )


@pytest.mark.asyncio
@pytest.mark.parametrize("setup_params", FEATURE_ENABLED_PARAMS)
async def test_event_link_state_delayed_packet(
    setup_params: List[SetupParameters],
) -> None:
    async with AsyncExitStack() as exit_stack:
        env = await setup_mesh_nodes(exit_stack, setup_params)
        alpha, beta = env.nodes
        client_alpha, client_beta = env.clients
        connection_alpha, connection_beta = [
            connmgr.connection for connmgr in env.connections
        ]

        await ping(connection_alpha, beta.ip_addresses[0])

        delay_s = resolve_idle_timeout(setup_params[0])
        await exit_stack.enter_async_context(
            add_outgoing_packets_delay(connection_beta, f"{delay_s}s")
        )

        # Waiting for the finish of the previous ping polling interval.
        await asyncio.sleep(WG_POLLING_PERIOD_S)

        # alpha will only receive the ICMP reply 20s after and
        # in the meantime beta's link state will go DOWN.
        ping_instant = asyncio.get_event_loop().time()
        with pytest.raises(asyncio.TimeoutError):
            await ping(connection_alpha, beta.ip_addresses[0], WG_POLLING_PERIOD_S)

        await client_alpha.wait_for_link_state(
            beta.public_key, LinkState.DOWN, resolve_idle_timeout(setup_params[0])
        )

        time_elapsed_since_ping = asyncio.get_event_loop().time() - ping_instant
        time_left_for_icmp_arrival = max(0, delay_s - time_elapsed_since_ping)
        await client_alpha.wait_for_link_state(
            beta.public_key,
            LinkState.UP,
            time_left_for_icmp_arrival + resolve_idle_timeout(setup_params[0]),
        )

        assert client_alpha.get_link_state_events(beta.public_key) == [
            LinkState.DOWN,
            LinkState.UP,
            LinkState.DOWN,
            LinkState.UP,
        ]
        assert client_beta.get_link_state_events(alpha.public_key) == [
            LinkState.DOWN,
            LinkState.UP,
        ]



