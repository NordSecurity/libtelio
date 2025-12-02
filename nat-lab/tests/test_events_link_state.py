import asyncio
import config
import pytest
from contextlib import AsyncExitStack
from helpers import SetupParameters, setup_mesh_nodes, setup_environment
from typing import List, Tuple
from utils import stun
from utils.bindings import (
    default_features,
    EndpointProvider,
    FeatureLinkDetection,
    FeatureWireguard,
    FeaturePersistentKeepalive,
    FeaturePolling,
    LinkState,
    NodeState,
    PathType,
    RelayState,
    TelioAdapterType,
)
from utils.connection import Connection, ConnectionTag, TargetOS
from utils.connection_util import add_outgoing_packets_delay, toggle_secondary_adapter
from utils.ping import ping

WG_POLLING_PERIOD_S = 1
WG_PASSIVE_KEEPALIVE_S = 10
MAX_RTT_ALLOWED_S = 1
# The duration which after a link is considered not to be up. (ie: PossibleDown->Down)
LINK_STATE_TIMEOUT_S = WG_PASSIVE_KEEPALIVE_S + MAX_RTT_ALLOWED_S
POSSIBLE_DOWN_DELAY = 3
# Enhanced detection (ED) issues a ping when there's the Up->PossibleDown link state transition,
# if no reply is received for LINK_STATE_TIMEOUT_S the link state will transit to Down.
POSSIBLE_DOWN_DELAY_ED = LINK_STATE_TIMEOUT_S
# As observed, detection in practice took 20-50% beyond LINK_STATE_TIMEOUT_S, thus a 50% tolerance is enough
# to detect down link state, with or without ED, whether on personal setup or on CI.
# If the tests happen to be flaky, this value shouldn't be increased.
TOLERANCE = 1.5
# The time by which we would expect to emit at least one link-state event, when tx_ts > rx_ts and none rx packet for the same period.
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
    direct: bool = False,
    vpn: bool = False,
) -> List[SetupParameters]:
    if enhaced_detection:
        count = 1
    else:
        count = 0

    features = default_features(enable_link_detection=False, enable_direct=direct)
    features.link_detection = FeatureLinkDetection(
        rtt_seconds=MAX_RTT_ALLOWED_S, no_of_pings=count, use_for_downgrade=False
    )
    features_default_wg_persistent_keepalive = features.wireguard.persistent_keepalive

    if direct and features.direct:
        features.direct.providers = [EndpointProvider.STUN]
        # Required to trigger direct connection renewal after network switch
        features.wireguard.persistent_keepalive.direct = (
            features_default_wg_persistent_keepalive.direct
        )
    elif vpn:
        # TODO: Remove this if you're adding a "vpn with mesh" test
        assert len(cfg) == 1
        features.wireguard.persistent_keepalive.vpn = (
            features_default_wg_persistent_keepalive.vpn
        )
    else:
        features.wireguard = long_persistent_keepalive_periods()

    return [
        SetupParameters(
            connection_tag=tag,
            adapter_type_override=adapter,
            features=features,
            # TODO: Remove this if you're adding a "vpn with mesh" test
            is_meshnet=not vpn,
        )
        for tag, adapter in cfg
    ]


FEATURE_ENABLED_PARAMS_RELAY = [
    param
    for param_pair in [
        (
            pytest.param(
                _generate_setup_parameter_pair(
                    [
                        (tag, adapter),
                        (
                            ConnectionTag.DOCKER_CONE_CLIENT_2,
                            TelioAdapterType.NEP_TUN,
                        ),
                    ],
                    enhaced_detection=False,
                ),
                marks=pytest.mark.windows if tag is ConnectionTag.VM_WINDOWS_1 else (),
            ),
            pytest.param(
                _generate_setup_parameter_pair(
                    [
                        (tag, adapter),
                        (
                            ConnectionTag.DOCKER_CONE_CLIENT_2,
                            TelioAdapterType.NEP_TUN,
                        ),
                    ],
                    enhaced_detection=True,
                ),
                marks=pytest.mark.windows if tag is ConnectionTag.VM_WINDOWS_1 else (),
            ),
        )
        for tag, adapter in [
            (ConnectionTag.DOCKER_CONE_CLIENT_1, TelioAdapterType.LINUX_NATIVE_TUN),
            (ConnectionTag.DOCKER_CONE_CLIENT_1, TelioAdapterType.NEP_TUN),
            (ConnectionTag.VM_WINDOWS_1, TelioAdapterType.WINDOWS_NATIVE_TUN),
        ]
    ]
    for param in param_pair
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
@pytest.mark.parametrize("setup_params", FEATURE_ENABLED_PARAMS_RELAY)
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
@pytest.mark.parametrize("setup_params", FEATURE_ENABLED_PARAMS_RELAY)
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
@pytest.mark.parametrize("setup_params", FEATURE_ENABLED_PARAMS_RELAY)
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
@pytest.mark.parametrize("setup_params", FEATURE_ENABLED_PARAMS_RELAY)
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
        # Stopping beta generates rx/tx traffic with alpha, so wait 2 seconds before the next ping to skip the current
        # polling interval and therefore guarantee that only tx increases (relatively to alpha->beta link)
        await asyncio.sleep(WG_POLLING_PERIOD_S * 2)

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
            "--insert",
            "INPUT",
            "--protocol",
            "icmp",
            "--icmp-type",
            "echo-request",
            "--jump",
            "DROP",
        ])
        await proc.execute()

    async def __aexit__(self, *_):
        proc = self._conn.create_process([
            "iptables",
            "--delete",
            "INPUT",
            "--protocol",
            "icmp",
            "--icmp-type",
            "echo-request",
            "--jump",
            "DROP",
        ])
        await proc.execute()


@pytest.mark.asyncio
@pytest.mark.parametrize("setup_params", FEATURE_ENABLED_PARAMS_RELAY)
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

        # After this ping beta's wireguard drivers will have ts_tx > ts_rx (link state feature will probably have ts_tx == ts_rx)
        await ping(connection_alpha, beta.ip_addresses[0])

        async with ICMP_control(connection_beta):
            with pytest.raises(asyncio.TimeoutError):
                await ping(connection_alpha, beta.ip_addresses[0], WG_POLLING_PERIOD_S)

            # If there was no connection, alpha->beta DOWN link state should be detected after 14-21s (ie: IDLE_TIMEOUT_S),
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
@pytest.mark.parametrize("setup_params", FEATURE_ENABLED_PARAMS_RELAY)
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
        await asyncio.sleep(WG_POLLING_PERIOD_S * 2)

        # alpha will only receive the ICMP reply 20s after,
        # in the meantime alpha->beta link state goes DOWN.
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


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "setup_params",
    [
        pytest.param(
            _generate_setup_parameter_pair(
                [
                    (ConnectionTag.DOCKER_SHARED_CLIENT_1, TelioAdapterType.NEP_TUN),
                    (ConnectionTag.DOCKER_CONE_CLIENT_2, TelioAdapterType.NEP_TUN),
                ],
                enhaced_detection=False,
                direct=False,
            ),
        ),
        pytest.param(
            _generate_setup_parameter_pair(
                [
                    (ConnectionTag.DOCKER_SHARED_CLIENT_1, TelioAdapterType.NEP_TUN),
                    (ConnectionTag.DOCKER_CONE_CLIENT_2, TelioAdapterType.NEP_TUN),
                ],
                enhaced_detection=True,
                direct=False,
            ),
        ),
        pytest.param(
            _generate_setup_parameter_pair(
                [
                    (
                        ConnectionTag.DOCKER_SHARED_CLIENT_1,
                        TelioAdapterType.LINUX_NATIVE_TUN,
                    ),
                    (ConnectionTag.DOCKER_CONE_CLIENT_2, TelioAdapterType.NEP_TUN),
                ],
                enhaced_detection=False,
                direct=False,
            ),
        ),
        pytest.param(
            _generate_setup_parameter_pair(
                [
                    (
                        ConnectionTag.DOCKER_SHARED_CLIENT_1,
                        TelioAdapterType.LINUX_NATIVE_TUN,
                    ),
                    (ConnectionTag.DOCKER_CONE_CLIENT_2, TelioAdapterType.NEP_TUN),
                ],
                enhaced_detection=True,
                direct=False,
            ),
        ),
        pytest.param(
            _generate_setup_parameter_pair(
                [
                    (ConnectionTag.VM_WINDOWS_1, TelioAdapterType.WINDOWS_NATIVE_TUN),
                    (ConnectionTag.DOCKER_CONE_CLIENT_1, TelioAdapterType.NEP_TUN),
                ],
                enhaced_detection=False,
                direct=False,
            ),
            marks=pytest.mark.windows,
        ),
        pytest.param(
            _generate_setup_parameter_pair(
                [
                    (ConnectionTag.VM_WINDOWS_1, TelioAdapterType.WINDOWS_NATIVE_TUN),
                    (ConnectionTag.DOCKER_CONE_CLIENT_1, TelioAdapterType.NEP_TUN),
                ],
                enhaced_detection=True,
                direct=False,
            ),
            marks=pytest.mark.windows,
        ),
    ],
)
async def test_event_link_detection_after_disabling_ethernet_adapter(
    setup_params: List[SetupParameters],
) -> None:
    async with AsyncExitStack() as exit_stack:
        env = await setup_mesh_nodes(exit_stack, setup_params)
        _, beta = env.nodes
        client_alpha, _ = env.clients
        conn_mgr_alpha, connection_alpha = (
            env.connections[0],
            env.connections[0].connection,
        )

        await ping(connection_alpha, beta.ip_addresses[0])

        # Switch to secondary network interface so that we can disable it while
        # keeping the container/VM connection alive through the primary interface.
        await conn_mgr_alpha.network_switcher.switch_to_secondary_network()
        await client_alpha.notify_network_change()
        await client_alpha.wait_for_event_on_any_derp([RelayState.CONNECTED])

        # We can think that after this ping beta->alpha will have tx_ts > rx_ts (ICMP reply),
        # however the counters have a granularity (ie: update rate) of 1s (=WG polling period) thus
        # tx_ts > rx_ts is not guaranteed and most of the times it'll be tx_ts == rx_ts.
        #
        # See comment below about the link state assertion on Beta. (*)
        await ping(connection_alpha, beta.ip_addresses[0])

        await exit_stack.enter_async_context(
            toggle_secondary_adapter(connection_alpha, False)
        )

        # notify_network_change() drops every socket, thus generating some traffic with beta. Waiting before the next ping
        # will guarantee a different polling interval where tx is the only counter to be increased
        await asyncio.sleep(WG_POLLING_PERIOD_S * 2)

        with pytest.raises(asyncio.TimeoutError):
            await ping(connection_alpha, beta.ip_addresses[0], WG_POLLING_PERIOD_S)

        # On some implementations (eg: WireguardNT) TX packet counter doesn't increase when the adapter is
        # disabled, which means link state detection might fail.
        await client_alpha.wait_for_link_state(
            beta.public_key, LinkState.DOWN, resolve_idle_timeout(setup_params[0])
        )
        assert client_alpha.get_link_state_events(beta.public_key) == [
            LinkState.DOWN,
            LinkState.UP,
            LinkState.DOWN,
        ]
        # (*) At this stage, we cannot avail beta->alpha link state due to the counters update rate (polling period is 1s).
        # tx_ts > rx_ts can only be guaranteed after the keepalive timeout (10s) + rekey timeout (5s) when it triggers the handshake,
        # IDLE_TIMEOUT_S seconds after, the down link state should be detected.
        # Alternatively we could ping alpha after disabling its interface which will make tx_ts > rx_ts.
        #
        # assert client_beta.get_link_state_events(alpha.public_key) == [
        #     LinkState.DOWN,
        #     LinkState.UP,
        # ]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "setup_params",
    [
        pytest.param(
            _generate_setup_parameter_pair(
                [
                    (ConnectionTag.DOCKER_SHARED_CLIENT_1, TelioAdapterType.NEP_TUN),
                    (ConnectionTag.DOCKER_CONE_CLIENT_2, TelioAdapterType.NEP_TUN),
                ],
                enhaced_detection=False,
                direct=True,
            ),
        ),
        pytest.param(
            _generate_setup_parameter_pair(
                [
                    (ConnectionTag.DOCKER_SHARED_CLIENT_1, TelioAdapterType.NEP_TUN),
                    (ConnectionTag.DOCKER_CONE_CLIENT_2, TelioAdapterType.NEP_TUN),
                ],
                enhaced_detection=True,
                direct=True,
            ),
        ),
        pytest.param(
            _generate_setup_parameter_pair(
                [
                    (ConnectionTag.VM_WINDOWS_1, TelioAdapterType.WINDOWS_NATIVE_TUN),
                    (ConnectionTag.DOCKER_CONE_CLIENT_2, TelioAdapterType.NEP_TUN),
                ],
                enhaced_detection=False,
                direct=True,
            ),
            marks=[
                pytest.mark.windows,
                pytest.mark.xfail(reason="Expected failure on Windows, see LLT-5073"),
            ],
        ),
        pytest.param(
            _generate_setup_parameter_pair(
                [
                    (ConnectionTag.VM_WINDOWS_1, TelioAdapterType.WINDOWS_NATIVE_TUN),
                    (ConnectionTag.DOCKER_CONE_CLIENT_2, TelioAdapterType.NEP_TUN),
                ],
                enhaced_detection=True,
                direct=True,
            ),
            marks=[
                pytest.mark.windows,
                pytest.mark.xfail(reason="Expected failure on Windows, see LLT-5073"),
            ],
        ),
    ],
)
async def test_event_link_detection_after_disabling_ethernet_adapter_direct_path(
    setup_params: List[SetupParameters],
) -> None:
    async with AsyncExitStack() as exit_stack:
        env = await setup_mesh_nodes(exit_stack, setup_params)
        alpha, beta = env.nodes
        client_alpha, client_beta = env.clients
        conn_mgr_alpha, connection_alpha = (
            env.connections[0],
            env.connections[0].connection,
        )

        await ping(connection_alpha, beta.ip_addresses[0])

        # Switch to secondary network interface so that we can disable it while
        # keeping the container/VM connection alive through the primary interface.
        await conn_mgr_alpha.network_switcher.switch_to_secondary_network()

        # Beta doesn't change its endpoint, so WG roaming may be used by alpha node to restore
        # the connection, so no node event is logged in that case
        await asyncio.gather(
            client_alpha.notify_network_change(),
            client_alpha.wait_for_event_on_any_derp([RelayState.CONNECTED]),
            client_beta.wait_for_event_peer(
                alpha.public_key,
                [NodeState.CONNECTED],
                [PathType.RELAY],
                link_state=LinkState.UP,
            ),
            client_beta.wait_for_event_peer(
                alpha.public_key,
                [NodeState.CONNECTED],
                [PathType.DIRECT],
                link_state=LinkState.UP,
            ),
        )

        # We can think that after this ping beta->alpha will have tx_ts > rx_ts (ICMP reply),
        # however the counters have a granularity (ie: update rate) of 1s (=WG polling period) thus
        # tx_ts > rx_ts is not guaranteed and most of the times it'll be tx_ts == rx_ts.
        #
        # See comment below about the link state assertion on Beta. (*)
        await ping(connection_alpha, beta.ip_addresses[0])

        await exit_stack.enter_async_context(
            toggle_secondary_adapter(connection_alpha, False)
        )

        # notify_network_change() drops every socket, thus generating some traffic with beta. Waiting before the next ping
        # will guarantee a different polling interval where tx is the only counter to be increased
        await asyncio.sleep(WG_POLLING_PERIOD_S * 2)

        with pytest.raises(asyncio.TimeoutError):
            await ping(connection_alpha, beta.ip_addresses[0], WG_POLLING_PERIOD_S)

        # On some implementations (eg: WireguardNT) TX packet counter doesn't increase for packets unsucessfully
        # sent, which happens when the pathtype is direct and the adapter is disabled. When that happens link state detection will
        # not work. (LLT-5073)
        # However after 3xdirect keep alives the connection is downgraded and any eventual packets will be successfully sent
        # from the WireguardNT perspective, because the following hop is the proxy socket at localhost (relayed peer endpoint)
        # before going to the disabled NIC.
        await client_alpha.wait_for_link_state(
            beta.public_key, LinkState.DOWN, resolve_idle_timeout(setup_params[0])
        )
        assert client_alpha.get_link_state_events(beta.public_key) == [
            LinkState.DOWN,
            LinkState.UP,
            LinkState.DOWN,
        ]
        # It's possible that beta->alpha has already detected the DOWN link state at this point due to the session keeper keepalive (ie: direct keepalive->5s)
        #
        # (*) At this stage, we cannot avail beta->alpha link state due to the counters update rate (polling period is 1s).
        # tx_ts > rx_ts can only be guaranteed after the keepalive timeout (10s) + rekey timeout (5s) when it triggers the handshake,
        # IDLE_TIMEOUT_S seconds after, the down link state should be detected.
        # Alternatively we could ping alpha after disabling its interface which will make tx_ts > rx_ts.
        #
        # assert client_beta.get_link_state_events(alpha.public_key) == [
        #     LinkState.DOWN,
        #     LinkState.UP,
        # ]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "alpha_setup_params",
    [
        pytest.param(
            _generate_setup_parameter_pair(
                [
                    (ConnectionTag.DOCKER_SHARED_CLIENT_1, TelioAdapterType.NEP_TUN),
                ],
                enhaced_detection=False,
                vpn=True,
            ),
        ),
        pytest.param(
            _generate_setup_parameter_pair(
                [
                    (ConnectionTag.DOCKER_SHARED_CLIENT_1, TelioAdapterType.NEP_TUN),
                ],
                enhaced_detection=True,
                vpn=True,
            ),
        ),
        pytest.param(
            _generate_setup_parameter_pair(
                [
                    (ConnectionTag.VM_WINDOWS_1, TelioAdapterType.WINDOWS_NATIVE_TUN),
                ],
                enhaced_detection=False,
                vpn=True,
            ),
            marks=[
                pytest.mark.windows,
                pytest.mark.xfail(reason="Expected failure on Windows, see LLT-5073"),
            ],
        ),
        pytest.param(
            _generate_setup_parameter_pair(
                [
                    (ConnectionTag.VM_WINDOWS_1, TelioAdapterType.WINDOWS_NATIVE_TUN),
                ],
                enhaced_detection=True,
                vpn=True,
            ),
            marks=[
                pytest.mark.windows,
                pytest.mark.xfail(reason="Expected failure on Windows, see LLT-5073"),
            ],
        ),
    ],
)
async def test_event_link_detection_after_disabling_ethernet_adapter_with_vpn(
    alpha_setup_params: List[SetupParameters],
) -> None:
    async with AsyncExitStack() as exit_stack:
        env = await exit_stack.enter_async_context(
            setup_environment(exit_stack, alpha_setup_params, prepare_vpn=True)
        )
        client_alpha = env.clients[0]
        conn_mgr_alpha, connection_alpha = (
            env.connections[0],
            env.connections[0].connection,
        )

        wg_server = config.WG_SERVER
        vpn_public_key = str(wg_server["public_key"])
        vpn_ipv4 = str(wg_server["ipv4"])
        await client_alpha.connect_to_vpn(
            vpn_ipv4, int(wg_server["port"]), vpn_public_key, link_state_enabled=True
        )

        await ping(connection_alpha, config.PHOTO_ALBUM_IP)

        ip = await stun.get(connection_alpha, config.STUN_SERVER)
        assert ip == vpn_ipv4, f"wrong public IP when connected to VPN {ip}"

        # Switch to secondary network interface so that we can disable it while
        # keeping the container/VM connection alive through the primary interface.
        await conn_mgr_alpha.network_switcher.switch_to_secondary_network()
        await client_alpha.notify_network_change()

        # See "test_vpn_network_switch" notes
        if connection_alpha.target_os == TargetOS.Windows:
            await asyncio.sleep(1)

        await ping(connection_alpha, config.PHOTO_ALBUM_IP)

        ip = await stun.get(connection_alpha, config.STUN_SERVER)
        assert ip == vpn_ipv4, f"wrong public IP when connected to VPN {ip}"

        await exit_stack.enter_async_context(
            toggle_secondary_adapter(connection_alpha, False)
        )

        # notify_network_change() drops every socket, thus generating some traffic with beta. Waiting before the next ping
        # will guarantee a different polling interval where tx is the only counter to be increased
        await asyncio.sleep(WG_POLLING_PERIOD_S * 2)

        with pytest.raises(asyncio.TimeoutError):
            await ping(connection_alpha, config.PHOTO_ALBUM_IP, WG_POLLING_PERIOD_S)

        # On some implementations (eg: WireguardNT) TX packet counter doesn't increase for packets unsucessfully
        # sent, which happens when the pathtype is direct and the adapter is disabled. When that happens link state detection will
        # not work. (LLT-5073)
        # However after 3xdirect keep alives the connection is downgraded and any eventual packets will be successfully sent
        # from the WireguardNT perspective, because the following hop is the proxy socket at localhost (relayed peer endpoint)
        # before going to the disabled interface.
        await client_alpha.wait_for_link_state(
            vpn_public_key, LinkState.DOWN, resolve_idle_timeout(alpha_setup_params[0])
        )
        assert client_alpha.get_link_state_events(vpn_public_key) == [
            LinkState.DOWN,
            LinkState.UP,
            LinkState.DOWN,
        ]
