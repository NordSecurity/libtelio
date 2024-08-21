# pylint: disable=too-many-lines

import asyncio
import base64
import pytest
import subprocess
import telio
from config import (
    WG_SERVER,
    STUN_SERVER,
    STUNV6_SERVER,
    DERP_PRIMARY,
    DERP_SECONDARY,
    DERP_TERTIARY,
)
from contextlib import AsyncExitStack
from helpers import connectivity_stack
from mesh_api import API, Node
from typing import List, Optional
from utils import testing, stun
from utils.analytics import fetch_moose_events, DERP_BIT, WG_BIT, IPV4_BIT, IPV6_BIT
from utils.analytics.event_validator import (
    CategoryValidator,
    ConnectivityMatrixValidator,
    DerpConnInfoValidator,
    ExternalLinksValidator,
    EventValidator,
    FingerprintValidator,
    MembersNatTypeValidator,
    MembersValidator,
    NameValidator,
    NatTraversalConnInfoValidator,
    ReceivedDataValidator,
    RttValidator,
    RttLossValidator,
    Rtt6LossValidator,
    Rtt6Validator,
    SentDataValidator,
    SelfNatTypeValidator,
    ALPHA_FINGERPRINT,
    BETA_FINGERPRINT,
    GAMMA_FINGERPRINT,
    NODES_FINGERPRINTS,
)
from utils.bindings import (
    default_features,
    Features,
    FeatureQoS,
    FeatureEndpointProvidersOptimization,
    EndpointProvider,
    RttType,
    PathType,
    NodeState,
    RelayState,
)
from utils.connection import Connection
from utils.connection_tracker import ConnectionLimits
from utils.connection_util import (
    generate_connection_tracker_config,
    ConnectionTag,
    container_id,
    new_connection_with_conn_tracker,
    new_connection_by_tag,
    add_outgoing_packets_delay,
)
from utils.ping import ping
from utils.router import IPStack, IPProto
from utils.telio_log_notifier import TelioLogNotifier

CONTAINER_EVENT_PATH = "/event.db"
CONTAINER_EVENT_BACKUP_PATH = "/event_backup.db"
ALPHA_EVENTS_PATH = "./alpha-events.db"
BETA_EVENTS_PATH = "./beta-events.db"
GAMMA_EVENTS_PATH = "./gamma-events.db"

DOCKER_CONE_GW_1_IPv4 = "10.0.254.1"
DOCKER_CONE_GW_1_IPv6 = "2001:db8:85a4::1000:2541"

DERP_SERVERS_STRS = [
    f"{DERP_PRIMARY.ipv4}:{DERP_PRIMARY.relay_port}",
    f"{DERP_SECONDARY.ipv4}:{DERP_SECONDARY.relay_port}",
    f"{DERP_TERTIARY.ipv4}:{DERP_TERTIARY.relay_port}",
]

DEFAULT_WAITING_TIME = 5
DEFAULT_CHECK_INTERVAL = 2
DEFAULT_CHECK_TIMEOUT = 60
COLLECT_NAT_TYPE = False
RTT_INTERVAL = 10

IP_STACK_TEST_CONFIGS = [
    pytest.param(
        IPStack.IPv4,
        IPStack.IPv4,
        marks=pytest.mark.ipv4,
    ),
    pytest.param(
        IPStack.IPv6,
        IPStack.IPv6,
        marks=pytest.mark.ipv6,
    ),
    pytest.param(
        IPStack.IPv4v6,
        IPStack.IPv4v6,
        marks=pytest.mark.ipv4v6,
    ),
    pytest.param(
        IPStack.IPv4,
        IPStack.IPv4v6,
        marks=pytest.mark.ipv4v6,
    ),
    pytest.param(
        IPStack.IPv6,
        IPStack.IPv4v6,
        marks=pytest.mark.ipv4v6,
    ),
]


def build_telio_features(initial_heartbeat_interval: int = 300) -> Features:
    features = default_features(
        enable_lana=(CONTAINER_EVENT_PATH, False),
        enable_direct=True,
        enable_nurse=True,
    )
    assert features.direct
    features.direct.providers = [EndpointProvider.STUN]
    features.direct.endpoint_providers_optimization = (
        FeatureEndpointProvidersOptimization(
            optimize_direct_upgrade_stun=False,
            optimize_direct_upgrade_upnp=False,
        )
    )
    assert features.nurse
    features.nurse.initial_heartbeat_interval = initial_heartbeat_interval
    features.nurse.qos = FeatureQoS(
        rtt_types=[RttType.PING],
        rtt_interval=RTT_INTERVAL,
        buckets=5,
        rtt_tries=1,
    )
    features.nurse.enable_nat_type_collection = COLLECT_NAT_TYPE
    return features


async def clean_container(connection: Connection):
    await connection.create_process(["rm", "-f", CONTAINER_EVENT_PATH]).execute()
    await connection.create_process(["rm", "-f", CONTAINER_EVENT_BACKUP_PATH]).execute()
    await connection.create_process(
        ["rm", "-f", CONTAINER_EVENT_PATH + "-journal"]
    ).execute()


def get_moose_db_file(container_tag, container_path, container_backup_path, local_path):
    subprocess.run(["rm", "-f", local_path])
    # sqlite3 -bail -batch moose.db "BEGIN EXCLUSIVE TRANSACTION; SELECT 1; ROLLBACK;" > /dev/null
    subprocess.run([
        "docker",
        "exec",
        "--privileged",
        container_id(container_tag),
        "sqlite3",
        container_path,
        f".backup {container_backup_path}",
    ])
    subprocess.run([
        "docker",
        "cp",
        container_id(container_tag) + ":" + container_backup_path,
        local_path,
    ])


async def wait_for_event_dump(container, events_path, nr_events):
    start_time = asyncio.get_event_loop().time()
    events = []
    while asyncio.get_event_loop().time() - start_time < DEFAULT_CHECK_TIMEOUT:
        get_moose_db_file(
            container, CONTAINER_EVENT_PATH, CONTAINER_EVENT_BACKUP_PATH, events_path
        )
        events = fetch_moose_events(events_path)
        if len(events) == nr_events:
            print(f"Found db from {container} with the expected {nr_events}.")
            return events
        await asyncio.sleep(DEFAULT_CHECK_INTERVAL)
    print(
        f"Failed looking db from {container}, expected {nr_events} but"
        f" {len(events)} were found."
    )
    return None


async def ping_node(
    initiator_conn: Connection,
    initiator: Node,
    target: Node,
    preffered_proto: IPProto = IPProto.IPv4,
):
    chosen_stack = choose_peer_stack(initiator.ip_stack, target.ip_stack)

    if chosen_stack == IPStack.IPv4:
        proto = IPProto.IPv4
    elif chosen_stack == IPStack.IPv6:
        proto = IPProto.IPv6
    elif chosen_stack == IPStack.IPv4v6:
        proto = preffered_proto
    else:
        # Impossibru
        return

    await ping(
        initiator_conn,
        testing.unpack_optional(target.get_ip_address(proto)),
    )


def choose_peer_stack(node_one: IPStack, node_two: IPStack) -> Optional[IPStack]:
    if (
        (node_one, node_two) == (IPStack.IPv4, IPStack.IPv4)
        or (node_one, node_two) == (IPStack.IPv4v6, IPStack.IPv4)
        or (node_one, node_two)
        == (
            IPStack.IPv4,
            IPStack.IPv4v6,
        )
    ):
        return IPStack.IPv4

    if (
        (node_one, node_two) == (IPStack.IPv6, IPStack.IPv6)
        or (node_one, node_two) == (IPStack.IPv4v6, IPStack.IPv6)
        or (node_one, node_two)
        == (
            IPStack.IPv6,
            IPStack.IPv4v6,
        )
    ):
        return IPStack.IPv6

    if (node_one, node_two) == (IPStack.IPv4v6, IPStack.IPv4v6):
        return IPStack.IPv4v6

    return None


def ip_stack_to_bits(ip_stack: IPStack) -> int:
    if ip_stack == IPStack.IPv4:
        return IPV4_BIT
    if ip_stack == IPStack.IPv6:
        return IPV6_BIT

    # IPStack.IPv4v6
    return IPV4_BIT | IPV6_BIT


async def start_alpha_beta_in_relay(
    exit_stack: AsyncExitStack,
    api: API,
    alpha: Node,
    beta: Node,
    connection_alpha: Connection,
    connection_beta: Connection,
    alpha_features: Features,
    beta_features: Features,
) -> tuple[telio.Client, telio.Client]:
    client_alpha = await exit_stack.enter_async_context(
        telio.Client(
            connection_alpha,
            alpha,
            telio_features=alpha_features,
            fingerprint=ALPHA_FINGERPRINT,
        ).run(api.get_meshnet_config(alpha.id))
    )

    client_beta = telio.Client(
        connection_beta,
        beta,
        telio_features=beta_features,
        fingerprint=BETA_FINGERPRINT,
    )

    if base64.b64decode(alpha.public_key) < base64.b64decode(beta.public_key):
        reporting_connection = connection_alpha
        losing_key = beta.public_key
    else:
        reporting_connection = connection_beta
        losing_key = alpha.public_key

    async with AsyncExitStack() as direct_disabled_exit_stack:
        telio_log_notifier = await direct_disabled_exit_stack.enter_async_context(
            TelioLogNotifier(reporting_connection).run()
        )

        for path in [DOCKER_CONE_GW_1_IPv4, DOCKER_CONE_GW_1_IPv6]:
            await direct_disabled_exit_stack.enter_async_context(
                client_beta.get_router().disable_path(path)
            )

        relayed_state_reported = telio_log_notifier.notify_output(
            f'Relayed peer state change for "{losing_key[:4]}...{losing_key[-4:]}" to Connected will be reported'
        )

        await exit_stack.enter_async_context(
            client_beta.run(api.get_meshnet_config(beta.id))
        )

        await relayed_state_reported.wait()

    return client_alpha, client_beta


async def run_default_scenario(
    exit_stack: AsyncExitStack,
    alpha_is_local,
    beta_is_local,
    gamma_is_local,
    alpha_has_vpn_connection=False,
    beta_has_vpn_connection=False,
    gamma_has_vpn_connection=False,
    alpha_ip_stack=IPStack.IPv4,
    beta_ip_stack=IPStack.IPv4,
    gamma_ip_stack=IPStack.IPv4,
):
    api = API()
    (alpha, beta, gamma) = api.default_config_three_nodes(
        alpha_is_local=alpha_is_local,
        beta_is_local=beta_is_local,
        gamma_is_local=gamma_is_local,
        alpha_ip_stack=alpha_ip_stack,
        beta_ip_stack=beta_ip_stack,
        gamma_ip_stack=gamma_ip_stack,
    )

    (connection_alpha, alpha_conn_tracker) = await exit_stack.enter_async_context(
        new_connection_with_conn_tracker(
            ConnectionTag.DOCKER_CONE_CLIENT_1,
            generate_connection_tracker_config(
                ConnectionTag.DOCKER_CONE_CLIENT_1,
                derp_1_limits=ConnectionLimits(1, 1),
                vpn_1_limits=ConnectionLimits(1 if alpha_has_vpn_connection else 0, 1),
            ),
        )
    )
    (connection_beta, beta_conn_tracker) = await exit_stack.enter_async_context(
        new_connection_with_conn_tracker(
            ConnectionTag.DOCKER_CONE_CLIENT_2,
            generate_connection_tracker_config(
                ConnectionTag.DOCKER_CONE_CLIENT_2,
                derp_1_limits=ConnectionLimits(1, 1),
                vpn_1_limits=ConnectionLimits(1 if beta_has_vpn_connection else 0, 1),
            ),
        )
    )
    (connection_gamma, gamma_conn_tracker) = await exit_stack.enter_async_context(
        new_connection_with_conn_tracker(
            ConnectionTag.DOCKER_SYMMETRIC_CLIENT_1,
            generate_connection_tracker_config(
                ConnectionTag.DOCKER_SYMMETRIC_CLIENT_1,
                derp_1_limits=ConnectionLimits(1, 1),
                vpn_1_limits=ConnectionLimits(1 if gamma_has_vpn_connection else 0, 1),
            ),
        )
    )

    await add_5ms_delay_to_connections(
        exit_stack, [connection_alpha, connection_beta, connection_gamma]
    )

    # Cleanup
    await clean_container(connection_alpha)
    await clean_container(connection_beta)
    await clean_container(connection_gamma)

    client_alpha, client_beta = await start_alpha_beta_in_relay(
        exit_stack,
        api,
        alpha,
        beta,
        connection_alpha,
        connection_beta,
        build_telio_features(),
        build_telio_features(),
    )
    client_gamma = await exit_stack.enter_async_context(
        telio.Client(
            connection_gamma,
            gamma,
            telio_features=build_telio_features(),
            fingerprint=GAMMA_FINGERPRINT,
        ).run(api.get_meshnet_config(gamma.id))
    )

    await asyncio.gather(
        client_alpha.wait_for_state_on_any_derp([RelayState.CONNECTED]),
        client_beta.wait_for_state_on_any_derp([RelayState.CONNECTED]),
        client_gamma.wait_for_state_on_any_derp([RelayState.CONNECTED]),
    )
    # Note: GAMMA is symmetric, so it will not connect to ALPHA or BETA in direct mode
    await asyncio.gather(
        client_alpha.wait_for_state_peer(
            beta.public_key,
            [NodeState.CONNECTED],
            [PathType.DIRECT],
        ),
        client_alpha.wait_for_state_peer(gamma.public_key, [NodeState.CONNECTED]),
        client_beta.wait_for_state_peer(
            alpha.public_key,
            [NodeState.CONNECTED],
            [PathType.DIRECT],
        ),
        client_beta.wait_for_state_peer(gamma.public_key, [NodeState.CONNECTED]),
        client_gamma.wait_for_state_peer(alpha.public_key, [NodeState.CONNECTED]),
        client_gamma.wait_for_state_peer(beta.public_key, [NodeState.CONNECTED]),
    )

    if alpha_has_vpn_connection:
        await client_alpha.connect_to_vpn(
            str(WG_SERVER["ipv4"]), int(WG_SERVER["port"]), str(WG_SERVER["public_key"])
        )

    if beta_has_vpn_connection:
        await client_beta.connect_to_vpn(
            str(WG_SERVER["ipv4"]), int(WG_SERVER["port"]), str(WG_SERVER["public_key"])
        )

    if gamma_has_vpn_connection:
        await client_gamma.connect_to_vpn(
            str(WG_SERVER["ipv4"]), int(WG_SERVER["port"]), str(WG_SERVER["public_key"])
        )

    await ping_node(connection_alpha, alpha, beta)
    await ping_node(connection_beta, beta, gamma)
    await ping_node(connection_gamma, gamma, alpha)

    await asyncio.sleep(DEFAULT_WAITING_TIME)
    if True in [
        alpha_has_vpn_connection,
        beta_has_vpn_connection,
        gamma_has_vpn_connection,
    ]:
        # VPN has an alternative address which QoS also tries to ping, therefore we should
        # wait for one more icmp timeout if that's the case.
        await asyncio.sleep(DEFAULT_WAITING_TIME)

    await client_alpha.trigger_event_collection()
    await client_beta.trigger_event_collection()
    await client_gamma.trigger_event_collection()

    alpha_events = await wait_for_event_dump(
        ConnectionTag.DOCKER_CONE_CLIENT_1, ALPHA_EVENTS_PATH, nr_events=1
    )
    assert alpha_events
    beta_events = await wait_for_event_dump(
        ConnectionTag.DOCKER_CONE_CLIENT_2, BETA_EVENTS_PATH, nr_events=1
    )
    assert beta_events
    gamma_events = await wait_for_event_dump(
        ConnectionTag.DOCKER_SYMMETRIC_CLIENT_1, GAMMA_EVENTS_PATH, nr_events=1
    )
    assert gamma_events

    assert await alpha_conn_tracker.get_out_of_limits() is None
    assert await beta_conn_tracker.get_out_of_limits() is None
    assert await gamma_conn_tracker.get_out_of_limits() is None

    (alpha_expected_states, beta_expected_states, gamma_expected_states) = (
        [
            (
                DERP_BIT
                | WG_BIT
                | ip_stack_to_bits(
                    testing.unpack_optional(
                        choose_peer_stack(alpha_ip_stack, beta_ip_stack)
                    )
                )
            ),
            (
                DERP_BIT
                | WG_BIT
                | ip_stack_to_bits(
                    testing.unpack_optional(
                        choose_peer_stack(alpha_ip_stack, gamma_ip_stack)
                    )
                )
            ),
            (
                DERP_BIT
                | WG_BIT
                | ip_stack_to_bits(
                    testing.unpack_optional(
                        choose_peer_stack(beta_ip_stack, gamma_ip_stack)
                    )
                )
            ),
        ]
        for _ in range(3)
    )

    return [
        alpha_events,
        beta_events,
        gamma_events,
        alpha_expected_states,
        beta_expected_states,
        gamma_expected_states,
        alpha.public_key,
        beta.public_key,
        gamma.public_key,
    ]


async def add_5ms_delay_to_connections(
    exit_stack: AsyncExitStack,
    connections: List[Connection],
):
    for connection in connections:
        await exit_stack.enter_async_context(
            add_outgoing_packets_delay(connection, "5ms")
        )


@pytest.mark.moose
@pytest.mark.asyncio
@pytest.mark.parametrize("alpha_ip_stack,beta_ip_stack", IP_STACK_TEST_CONFIGS)
async def test_lana_with_same_meshnet(
    alpha_ip_stack: IPStack, beta_ip_stack: IPStack
) -> None:
    async with AsyncExitStack() as exit_stack:
        gamma_ip_stack = IPStack.IPv4v6

        [
            alpha_events,
            beta_events,
            gamma_events,
            alpha_expected_states,
            beta_expected_states,
            gamma_expected_states,
            alpha_pubkey,
            beta_pubkey,
            gamma_pubkey,
        ] = await run_default_scenario(
            exit_stack=exit_stack,
            alpha_is_local=True,
            beta_is_local=True,
            gamma_is_local=True,
            alpha_ip_stack=alpha_ip_stack,
            beta_ip_stack=beta_ip_stack,
            gamma_ip_stack=gamma_ip_stack,
        )

        # Alpha has smallest public key when sorted lexicographically
        expected_meshnet_id = alpha_events[0].fp

        alpha_validator = (
            EventValidator.new_with_basic_validators(
                ALPHA_FINGERPRINT, meshnet_id=expected_meshnet_id
            )
            .add_rtt_validators([alpha_ip_stack, beta_ip_stack, gamma_ip_stack])
            .add_validator_list([
                ExternalLinksValidator(exists=False),
                ConnectivityMatrixValidator(
                    expected_states=alpha_expected_states,
                    exists=True,
                    no_of_connections=3,
                    all_connections_up=False,
                ),
                MembersValidator(
                    exists=True,
                    contains=NODES_FINGERPRINTS,
                ),
                SentDataValidator(
                    exists=True,
                    members=[BETA_FINGERPRINT, GAMMA_FINGERPRINT],
                    does_not_contain=["0:0:0:0:0"],
                ),
                ReceivedDataValidator(
                    exists=True,
                    members=[BETA_FINGERPRINT, GAMMA_FINGERPRINT],
                    does_not_contain=["0:0:0:0:0"],
                ),
                DerpConnInfoValidator(
                    exists=True,
                    servers=DERP_SERVERS_STRS,
                ),
                NatTraversalConnInfoValidator(
                    alpha_pubkey,
                    beta_pubkey,
                    False,
                    does_not_contain=["0:0:0:0:0:0"],
                    count=1,
                ),
            ])
        )
        beta_validator = (
            EventValidator.new_with_basic_validators(
                BETA_FINGERPRINT, meshnet_id=expected_meshnet_id
            )
            .add_rtt_validators([alpha_ip_stack, beta_ip_stack, gamma_ip_stack])
            .add_validator_list([
                ExternalLinksValidator(exists=False),
                ConnectivityMatrixValidator(
                    expected_states=beta_expected_states,
                    exists=True,
                    no_of_connections=3,
                    all_connections_up=False,
                ),
                MembersValidator(
                    exists=True,
                    contains=NODES_FINGERPRINTS,
                ),
                SentDataValidator(
                    exists=True,
                    members=[ALPHA_FINGERPRINT, GAMMA_FINGERPRINT],
                    does_not_contain=["0:0:0:0:0"],
                ),
                ReceivedDataValidator(
                    exists=True,
                    members=[ALPHA_FINGERPRINT, GAMMA_FINGERPRINT],
                    does_not_contain=["0:0:0:0:0"],
                ),
                DerpConnInfoValidator(
                    exists=True,
                    servers=DERP_SERVERS_STRS,
                ),
                NatTraversalConnInfoValidator(
                    beta_pubkey,
                    alpha_pubkey,
                    False,
                    does_not_contain=["0:0:0:0:0:0"],
                    count=1,
                ),
            ])
        )
        gamma_validator = (
            EventValidator.new_with_basic_validators(
                GAMMA_FINGERPRINT, meshnet_id=expected_meshnet_id
            )
            .add_rtt_validators([alpha_ip_stack, beta_ip_stack, gamma_ip_stack])
            .add_validator_list([
                ExternalLinksValidator(exists=False),
                ConnectivityMatrixValidator(
                    expected_states=gamma_expected_states,
                    exists=True,
                    no_of_connections=3,
                    all_connections_up=False,
                ),
                MembersValidator(
                    exists=True,
                    contains=NODES_FINGERPRINTS,
                ),
                SentDataValidator(
                    exists=True,
                    members=[ALPHA_FINGERPRINT, BETA_FINGERPRINT],
                    does_not_contain=["0:0:0:0:0"],
                ),
                ReceivedDataValidator(
                    exists=True,
                    members=[ALPHA_FINGERPRINT, BETA_FINGERPRINT],
                    does_not_contain=["0:0:0:0:0"],
                ),
                DerpConnInfoValidator(
                    exists=True,
                    servers=DERP_SERVERS_STRS,
                ),
                NatTraversalConnInfoValidator(
                    gamma_pubkey,
                    "",
                    True,
                ),
            ])
        )
        if COLLECT_NAT_TYPE:
            alpha_validator.add_validator_list([
                SelfNatTypeValidator("PortRestrictedCone"),
                MembersNatTypeValidator(
                    ["Symmetric", "PortRestrictedCone"],
                ),
            ])
            beta_validator.add_validator_list([
                SelfNatTypeValidator("PortRestrictedCone"),
                MembersNatTypeValidator(
                    ["PortRestrictedCone", "Symmetric"],
                ),
            ])
            gamma_validator.add_validator_list([
                SelfNatTypeValidator("Symmetric"),
                MembersNatTypeValidator(
                    ["PortRestrictedCone", "PortRestrictedCone"],
                ),
            ])

        res = alpha_validator.validate(alpha_events[0])
        assert res[0], res[1]
        res = beta_validator.validate(beta_events[0])
        assert res[0], res[1]
        res = gamma_validator.validate(gamma_events[0])
        assert res[0], res[1]


@pytest.mark.moose
@pytest.mark.asyncio
@pytest.mark.parametrize("alpha_ip_stack,beta_ip_stack", IP_STACK_TEST_CONFIGS)
async def test_lana_with_external_node(
    alpha_ip_stack: IPStack, beta_ip_stack: IPStack
) -> None:
    async with AsyncExitStack() as exit_stack:
        gamma_ip_stack = IPStack.IPv4v6

        [
            alpha_events,
            beta_events,
            gamma_events,
            alpha_expected_states,
            beta_expected_states,
            gamma_expected_states,
            alpha_pubkey,
            beta_pubkey,
            gamma_pubkey,
        ] = await run_default_scenario(
            exit_stack=exit_stack,
            alpha_is_local=True,
            beta_is_local=True,
            gamma_is_local=False,
            alpha_ip_stack=alpha_ip_stack,
            beta_ip_stack=beta_ip_stack,
            gamma_ip_stack=gamma_ip_stack,
        )

        alpha_validator = (
            EventValidator.new_with_basic_validators(ALPHA_FINGERPRINT)
            .add_rtt_validators([alpha_ip_stack, beta_ip_stack, gamma_ip_stack])
            .add_validator_list([
                ExternalLinksValidator(
                    exists=True,
                    contains=[GAMMA_FINGERPRINT],
                    does_not_contain=["vpn", alpha_events[0].fp, ALPHA_FINGERPRINT],
                    all_connections_up=False,
                    no_of_connections=1,
                    expected_states=alpha_expected_states,
                ),
                ConnectivityMatrixValidator(
                    expected_states=alpha_expected_states,
                    exists=True,
                    no_of_connections=1,
                    all_connections_up=False,
                ),
                MembersValidator(
                    exists=True,
                    contains=[ALPHA_FINGERPRINT, BETA_FINGERPRINT],
                    does_not_contain=[GAMMA_FINGERPRINT],
                ),
                SentDataValidator(
                    exists=True,
                    members=[BETA_FINGERPRINT, GAMMA_FINGERPRINT],
                    does_not_contain=["0:0:0:0:0"],
                ),
                ReceivedDataValidator(
                    exists=True,
                    members=[BETA_FINGERPRINT, GAMMA_FINGERPRINT],
                    does_not_contain=["0:0:0:0:0"],
                ),
                DerpConnInfoValidator(
                    exists=True,
                    servers=DERP_SERVERS_STRS,
                ),
                NatTraversalConnInfoValidator(
                    alpha_pubkey,
                    beta_pubkey,
                    False,
                    does_not_contain=["0:0:0:0:0:0"],
                    count=1,
                ),
            ])
        )
        beta_validator = (
            EventValidator.new_with_basic_validators(BETA_FINGERPRINT)
            .add_rtt_validators([alpha_ip_stack, beta_ip_stack, gamma_ip_stack])
            .add_validator_list([
                ExternalLinksValidator(
                    exists=True,
                    contains=[GAMMA_FINGERPRINT],
                    does_not_contain=["vpn", beta_events[0].fp, BETA_FINGERPRINT],
                    all_connections_up=False,
                    no_of_connections=1,
                    expected_states=beta_expected_states,
                ),
                ConnectivityMatrixValidator(
                    expected_states=beta_expected_states,
                    exists=True,
                    no_of_connections=1,
                    all_connections_up=False,
                ),
                MembersValidator(
                    exists=True,
                    contains=[ALPHA_FINGERPRINT, BETA_FINGERPRINT],
                    does_not_contain=[GAMMA_FINGERPRINT],
                ),
                SentDataValidator(
                    exists=True,
                    members=[ALPHA_FINGERPRINT, GAMMA_FINGERPRINT],
                    does_not_contain=["0:0:0:0:0"],
                ),
                ReceivedDataValidator(
                    exists=True,
                    members=[ALPHA_FINGERPRINT, GAMMA_FINGERPRINT],
                    does_not_contain=["0:0:0:0:0"],
                ),
                DerpConnInfoValidator(
                    exists=True,
                    servers=DERP_SERVERS_STRS,
                ),
                NatTraversalConnInfoValidator(
                    beta_pubkey,
                    alpha_pubkey,
                    False,
                    does_not_contain=["0:0:0:0:0:0"],
                    count=1,
                ),
            ])
        )
        gamma_validator = (
            EventValidator.new_with_basic_validators(GAMMA_FINGERPRINT)
            .add_rtt_validators([alpha_ip_stack, beta_ip_stack, gamma_ip_stack])
            .add_validator_list([
                ExternalLinksValidator(
                    exists=True,
                    contains=[ALPHA_FINGERPRINT, BETA_FINGERPRINT],
                    does_not_contain=["vpn", gamma_events[0].fp, GAMMA_FINGERPRINT],
                    all_connections_up=False,
                    no_of_connections=2,
                    expected_states=gamma_expected_states,
                ),
                ConnectivityMatrixValidator(exists=False),
                SentDataValidator(
                    exists=True,
                    members=[ALPHA_FINGERPRINT, BETA_FINGERPRINT],
                    does_not_contain=["0:0:0:0:0"],
                ),
                ReceivedDataValidator(
                    exists=True,
                    members=[ALPHA_FINGERPRINT, BETA_FINGERPRINT],
                    does_not_contain=["0:0:0:0:0"],
                ),
                DerpConnInfoValidator(
                    exists=True,
                    servers=DERP_SERVERS_STRS,
                ),
                NatTraversalConnInfoValidator(gamma_pubkey, "", True),
            ])
        )
        if COLLECT_NAT_TYPE:
            alpha_validator.add_validator_list([
                SelfNatTypeValidator("PortRestrictedCone"),
                MembersNatTypeValidator(
                    ["PortRestrictedCone", "Symmetric"],
                ),
            ])
            beta_validator.add_validator_list([
                SelfNatTypeValidator("PortRestrictedCone"),
                MembersNatTypeValidator(
                    ["PortRestrictedCone", "Symmetric"],
                ),
            ])
            gamma_validator.add_validator_list([
                SelfNatTypeValidator("Symmetric"),
                MembersNatTypeValidator(
                    ["PortRestrictedCone", "PortRestrictedCone"],
                ),
            ])

        res = alpha_validator.validate(alpha_events[0])
        assert res[0], res[1]
        res = beta_validator.validate(beta_events[0])
        assert res[0], res[1]
        res = gamma_validator.validate(gamma_events[0])
        assert res[0], res[1]

        # Validate alpha and beta have the same meshent id which is different from gamma's
        assert alpha_events[0].fp == beta_events[0].fp
        assert alpha_events[0].fp != gamma_events[0].fp


@pytest.mark.moose
@pytest.mark.asyncio
@pytest.mark.parametrize("alpha_ip_stack,beta_ip_stack", IP_STACK_TEST_CONFIGS)
async def test_lana_all_external(
    alpha_ip_stack: IPStack, beta_ip_stack: IPStack
) -> None:
    async with AsyncExitStack() as exit_stack:
        gamma_ip_stack = IPStack.IPv4v6

        [
            alpha_events,
            beta_events,
            gamma_events,
            alpha_expected_states,
            beta_expected_states,
            gamma_expected_states,
            alpha_pubkey,
            beta_pubkey,
            gamma_pubkey,
        ] = await run_default_scenario(
            exit_stack=exit_stack,
            alpha_is_local=False,
            beta_is_local=False,
            gamma_is_local=False,
            alpha_ip_stack=alpha_ip_stack,
            beta_ip_stack=beta_ip_stack,
            gamma_ip_stack=gamma_ip_stack,
        )

        alpha_validator = (
            EventValidator.new_with_basic_validators(ALPHA_FINGERPRINT)
            .add_rtt_validators([alpha_ip_stack, beta_ip_stack, gamma_ip_stack])
            .add_validator_list([
                ExternalLinksValidator(
                    exists=True,
                    contains=[BETA_FINGERPRINT, GAMMA_FINGERPRINT],
                    does_not_contain=["vpn", alpha_events[0].fp, ALPHA_FINGERPRINT],
                    all_connections_up=False,
                    no_of_connections=2,
                    expected_states=alpha_expected_states,
                ),
                ConnectivityMatrixValidator(exists=False),
                MembersValidator(
                    exists=True,
                    does_not_contain=[BETA_FINGERPRINT, GAMMA_FINGERPRINT],
                ),
                SentDataValidator(
                    exists=True,
                    members=[BETA_FINGERPRINT, GAMMA_FINGERPRINT],
                    does_not_contain=["0:0:0:0:0"],
                ),
                ReceivedDataValidator(
                    exists=True,
                    members=[BETA_FINGERPRINT, GAMMA_FINGERPRINT],
                    does_not_contain=["0:0:0:0:0"],
                ),
                DerpConnInfoValidator(
                    exists=True,
                    servers=DERP_SERVERS_STRS,
                ),
                NatTraversalConnInfoValidator(
                    alpha_pubkey,
                    beta_pubkey,
                    False,
                    does_not_contain=["0:0:0:0:0:0"],
                    count=1,
                ),
            ])
        )
        beta_validator = (
            EventValidator.new_with_basic_validators(BETA_FINGERPRINT)
            .add_rtt_validators([alpha_ip_stack, beta_ip_stack, gamma_ip_stack])
            .add_validator_list([
                ExternalLinksValidator(
                    exists=True,
                    contains=[ALPHA_FINGERPRINT, GAMMA_FINGERPRINT],
                    does_not_contain=["vpn", beta_events[0].fp, BETA_FINGERPRINT],
                    all_connections_up=False,
                    no_of_connections=2,
                    expected_states=beta_expected_states,
                ),
                ConnectivityMatrixValidator(exists=False),
                MembersValidator(
                    exists=True,
                    does_not_contain=[ALPHA_FINGERPRINT, GAMMA_FINGERPRINT],
                ),
                SentDataValidator(
                    exists=True,
                    members=[ALPHA_FINGERPRINT, GAMMA_FINGERPRINT],
                    does_not_contain=["0:0:0:0:0"],
                ),
                ReceivedDataValidator(
                    exists=True,
                    members=[ALPHA_FINGERPRINT, GAMMA_FINGERPRINT],
                    does_not_contain=["0:0:0:0:0"],
                ),
                DerpConnInfoValidator(
                    exists=True,
                    servers=DERP_SERVERS_STRS,
                ),
                NatTraversalConnInfoValidator(
                    beta_pubkey,
                    alpha_pubkey,
                    False,
                    does_not_contain=["0:0:0:0:0:0"],
                    count=1,
                ),
            ])
        )
        gamma_validator = (
            EventValidator.new_with_basic_validators(GAMMA_FINGERPRINT)
            .add_rtt_validators([alpha_ip_stack, beta_ip_stack, gamma_ip_stack])
            .add_validator_list([
                ExternalLinksValidator(
                    exists=True,
                    contains=[ALPHA_FINGERPRINT, BETA_FINGERPRINT],
                    does_not_contain=["vpn", gamma_events[0].fp, BETA_FINGERPRINT],
                    all_connections_up=False,
                    no_of_connections=2,
                    expected_states=gamma_expected_states,
                ),
                ConnectivityMatrixValidator(exists=False),
                MembersValidator(
                    exists=True,
                    does_not_contain=[ALPHA_FINGERPRINT, BETA_FINGERPRINT],
                ),
                SentDataValidator(
                    exists=True,
                    members=[ALPHA_FINGERPRINT, BETA_FINGERPRINT],
                    does_not_contain=["0:0:0:0:0"],
                ),
                ReceivedDataValidator(
                    exists=True,
                    members=[ALPHA_FINGERPRINT, BETA_FINGERPRINT],
                    does_not_contain=["0:0:0:0:0"],
                ),
                DerpConnInfoValidator(
                    exists=True,
                    servers=DERP_SERVERS_STRS,
                ),
                NatTraversalConnInfoValidator(
                    gamma_pubkey,
                    "",
                    True,
                ),
            ])
        )
        if COLLECT_NAT_TYPE:
            alpha_validator.add_validator_list([
                SelfNatTypeValidator("PortRestrictedCone"),
                MembersNatTypeValidator(
                    ["Symmetric", "PortRestrictedCone"],
                ),
            ])
            beta_validator.add_validator_list([
                SelfNatTypeValidator("PortRestrictedCone"),
                MembersNatTypeValidator(
                    ["PortRestrictedCone", "Symmetric"],
                ),
            ])
            gamma_validator.add_validator_list([
                SelfNatTypeValidator("Symmetric"),
                MembersNatTypeValidator(
                    ["PortRestrictedCone", "PortRestrictedCone"],
                ),
            ])

        res = alpha_validator.validate(alpha_events[0])
        assert res[0], res[1]
        res = beta_validator.validate(beta_events[0])
        assert res[0], res[1]
        res = gamma_validator.validate(gamma_events[0])
        assert res[0], res[1]

        # Validate all meshent ids are different
        assert alpha_events[0].fp != beta_events[0].fp
        assert alpha_events[0].fp != gamma_events[0].fp
        assert beta_events[0].fp != gamma_events[0].fp


@pytest.mark.moose
@pytest.mark.asyncio
@pytest.mark.parametrize("alpha_ip_stack,beta_ip_stack", IP_STACK_TEST_CONFIGS)
async def test_lana_with_vpn_connection(
    alpha_ip_stack: IPStack, beta_ip_stack: IPStack
) -> None:
    async with AsyncExitStack() as exit_stack:
        gamma_ip_stack = IPStack.IPv4v6

        [
            alpha_events,
            beta_events,
            gamma_events,
            alpha_expected_states,
            beta_expected_states,
            gamma_expected_states,
            alpha_pubkey,
            beta_pubkey,
            gamma_pubkey,
        ] = await run_default_scenario(
            exit_stack=exit_stack,
            alpha_is_local=True,
            beta_is_local=True,
            gamma_is_local=True,
            alpha_has_vpn_connection=True,
            beta_has_vpn_connection=False,
            gamma_has_vpn_connection=False,
            alpha_ip_stack=alpha_ip_stack,
            beta_ip_stack=beta_ip_stack,
            gamma_ip_stack=gamma_ip_stack,
        )

        # Alpha has smallest public key when sorted lexicographically
        expected_meshnet_id = alpha_events[0].fp

        alpha_validator = (
            EventValidator.new_with_basic_validators(
                ALPHA_FINGERPRINT, meshnet_id=expected_meshnet_id
            )
            .add_rtt_validators([alpha_ip_stack, beta_ip_stack, gamma_ip_stack])
            .add_validator_list([
                ExternalLinksValidator(
                    exists=True,
                    contains=["vpn"],
                    all_connections_up=False,
                    no_of_connections=1,
                    no_of_vpn=1,
                    expected_states=alpha_expected_states,
                ),
                ConnectivityMatrixValidator(
                    exists=True,
                    no_of_connections=3,
                    all_connections_up=False,
                    expected_states=alpha_expected_states,
                ),
                MembersValidator(
                    exists=True,
                    contains=NODES_FINGERPRINTS,
                ),
                SentDataValidator(
                    exists=True,
                    members=[BETA_FINGERPRINT, GAMMA_FINGERPRINT, "vpn"],
                    does_not_contain=["0:0:0:0:0"],
                ),
                ReceivedDataValidator(
                    exists=True,
                    members=[BETA_FINGERPRINT, GAMMA_FINGERPRINT, "vpn"],
                    does_not_contain=["0:0:0:0:0"],
                ),
                DerpConnInfoValidator(
                    exists=True,
                    servers=DERP_SERVERS_STRS,
                ),
                NatTraversalConnInfoValidator(
                    alpha_pubkey,
                    beta_pubkey,
                    False,
                    does_not_contain=["0:0:0:0:0:0"],
                    count=1,
                ),
            ])
        )

        beta_validator = (
            EventValidator.new_with_basic_validators(
                BETA_FINGERPRINT, meshnet_id=expected_meshnet_id
            )
            .add_rtt_validators([alpha_ip_stack, beta_ip_stack, gamma_ip_stack])
            .add_validator_list([
                ExternalLinksValidator(exists=False),
                ConnectivityMatrixValidator(
                    exists=True,
                    no_of_connections=3,
                    all_connections_up=False,
                    expected_states=beta_expected_states,
                ),
                MembersValidator(
                    exists=True,
                    contains=NODES_FINGERPRINTS,
                ),
                SentDataValidator(
                    exists=True,
                    members=[ALPHA_FINGERPRINT, GAMMA_FINGERPRINT],
                    does_not_contain=["0:0:0:0:0"],
                ),
                ReceivedDataValidator(
                    exists=True,
                    members=[ALPHA_FINGERPRINT, GAMMA_FINGERPRINT],
                    does_not_contain=["0:0:0:0:0"],
                ),
                DerpConnInfoValidator(
                    exists=True,
                    servers=DERP_SERVERS_STRS,
                ),
                NatTraversalConnInfoValidator(
                    beta_pubkey,
                    alpha_pubkey,
                    False,
                    does_not_contain=["0:0:0:0:0:0"],
                    count=1,
                ),
            ])
        )
        gamma_validator = (
            EventValidator.new_with_basic_validators(
                GAMMA_FINGERPRINT, meshnet_id=expected_meshnet_id
            )
            .add_rtt_validators([alpha_ip_stack, beta_ip_stack, gamma_ip_stack])
            .add_validator_list([
                ExternalLinksValidator(exists=False),
                ConnectivityMatrixValidator(
                    exists=True,
                    no_of_connections=3,
                    all_connections_up=False,
                    expected_states=gamma_expected_states,
                ),
                MembersValidator(
                    exists=True,
                    contains=NODES_FINGERPRINTS,
                ),
                SentDataValidator(
                    exists=True,
                    members=[ALPHA_FINGERPRINT, BETA_FINGERPRINT],
                    does_not_contain=["0:0:0:0:0"],
                ),
                ReceivedDataValidator(
                    exists=True,
                    members=[ALPHA_FINGERPRINT, BETA_FINGERPRINT],
                    does_not_contain=["0:0:0:0:0"],
                ),
                DerpConnInfoValidator(
                    exists=True,
                    servers=DERP_SERVERS_STRS,
                ),
                NatTraversalConnInfoValidator(
                    gamma_pubkey,
                    "",
                    True,
                ),
            ])
        )
        if COLLECT_NAT_TYPE:
            alpha_validator.add_validator_list([
                SelfNatTypeValidator("Symmetric"),
                MembersNatTypeValidator(
                    ["Symmetric", "PortRestrictedCone"],
                ),
            ])
            beta_validator.add_validator_list([
                SelfNatTypeValidator("PortRestrictedCone"),
                MembersNatTypeValidator(
                    ["Symmetric", "Symmetric"],
                ),
            ])
            gamma_validator.add_validator_list([
                SelfNatTypeValidator("Symmetric"),
                MembersNatTypeValidator(
                    ["Symmetric", "PortRestrictedCone"],
                ),
            ])

        res = alpha_validator.validate(alpha_events[0])
        assert res[0], res[1]
        res = beta_validator.validate(beta_events[0])
        assert res[0], res[1]
        res = gamma_validator.validate(gamma_events[0])
        assert res[0], res[1]


@pytest.mark.moose
@pytest.mark.asyncio
@pytest.mark.parametrize("alpha_ip_stack,beta_ip_stack", IP_STACK_TEST_CONFIGS)
async def test_lana_with_meshnet_exit_node(
    alpha_ip_stack: IPStack, beta_ip_stack: IPStack
):
    async with AsyncExitStack() as exit_stack:
        is_stun6_needed = (
            testing.unpack_optional(choose_peer_stack(alpha_ip_stack, beta_ip_stack))
            is IPStack.IPv6
        )

        api = API()
        (alpha, beta) = api.default_config_two_nodes(
            True, True, alpha_ip_stack=alpha_ip_stack, beta_ip_stack=beta_ip_stack
        )
        (connection_alpha, alpha_conn_tracker) = await exit_stack.enter_async_context(
            new_connection_with_conn_tracker(
                ConnectionTag.DOCKER_CONE_CLIENT_1,
                generate_connection_tracker_config(
                    ConnectionTag.DOCKER_CONE_CLIENT_1,
                    derp_1_limits=ConnectionLimits(1, 1),
                ),
            )
        )
        (connection_beta, beta_conn_tracker) = await exit_stack.enter_async_context(
            new_connection_with_conn_tracker(
                ConnectionTag.DOCKER_OPEN_INTERNET_CLIENT_DUAL_STACK,
                generate_connection_tracker_config(
                    ConnectionTag.DOCKER_OPEN_INTERNET_CLIENT_DUAL_STACK,
                    derp_1_limits=ConnectionLimits(1, 1),
                    stun6_limits=(
                        ConnectionLimits(1, 1)
                        if is_stun6_needed
                        else ConnectionLimits(0, 0)
                    ),
                    stun_limits=(
                        ConnectionLimits(1, 1)
                        if not is_stun6_needed
                        else ConnectionLimits(0, 0)
                    ),
                    ping_limits=ConnectionLimits(None, None),
                    ping6_limits=ConnectionLimits(None, None),
                ),
            )
        )

        await add_5ms_delay_to_connections(
            exit_stack, [connection_alpha, connection_beta]
        )

        await clean_container(connection_alpha)
        await clean_container(connection_beta)

        client_alpha, client_beta = await start_alpha_beta_in_relay(
            exit_stack,
            api,
            alpha,
            beta,
            connection_alpha,
            connection_beta,
            build_telio_features(),
            build_telio_features(),
        )

        await asyncio.gather(
            client_alpha.wait_for_state_on_any_derp([RelayState.CONNECTED]),
            client_beta.wait_for_state_on_any_derp([RelayState.CONNECTED]),
        )
        await asyncio.gather(
            client_alpha.wait_for_state_peer(
                beta.public_key, [NodeState.CONNECTED], [PathType.DIRECT]
            ),
            client_beta.wait_for_state_peer(
                alpha.public_key, [NodeState.CONNECTED], [PathType.DIRECT]
            ),
        )

        await ping(
            connection_alpha,
            testing.unpack_optional(
                beta.get_ip_address(IPProto.IPv6 if is_stun6_needed else IPProto.IPv4)
            ),
        )
        await client_beta.get_router().create_exit_node_route()
        await client_alpha.connect_to_exit_node(beta.public_key)
        ip_alpha = await stun.get(
            connection_alpha, STUN_SERVER if not is_stun6_needed else STUNV6_SERVER
        )
        ip_beta = await stun.get(
            connection_beta, STUN_SERVER if not is_stun6_needed else STUNV6_SERVER
        )
        assert ip_alpha == ip_beta

        await asyncio.sleep(DEFAULT_WAITING_TIME)

        await client_alpha.trigger_event_collection()
        await client_beta.trigger_event_collection()

        alpha_events = await wait_for_event_dump(
            ConnectionTag.DOCKER_CONE_CLIENT_1, ALPHA_EVENTS_PATH, nr_events=1
        )
        beta_events = await wait_for_event_dump(
            ConnectionTag.DOCKER_OPEN_INTERNET_CLIENT_DUAL_STACK,
            BETA_EVENTS_PATH,
            nr_events=1,
        )
        assert alpha_events
        assert beta_events

        alpha_validator = (
            EventValidator.new_with_basic_validators(ALPHA_FINGERPRINT)
            .add_rtt_validators([alpha_ip_stack, beta_ip_stack, None])
            .add_validator_list([
                ExternalLinksValidator(exists=False),
                ConnectivityMatrixValidator(
                    exists=True,
                    no_of_connections=1,
                    all_connections_up=False,
                    expected_states=[(
                        DERP_BIT
                        | WG_BIT
                        | ip_stack_to_bits(
                            testing.unpack_optional(
                                choose_peer_stack(alpha_ip_stack, beta_ip_stack)
                            )
                        )
                    )],
                ),
                MembersValidator(
                    exists=True,
                    contains=[ALPHA_FINGERPRINT, BETA_FINGERPRINT],
                ),
                SentDataValidator(
                    exists=True,
                    members=[BETA_FINGERPRINT],
                    does_not_contain=["0:0:0:0:0"],
                ),
                ReceivedDataValidator(
                    exists=True,
                    members=[BETA_FINGERPRINT],
                    does_not_contain=["0:0:0:0:0"],
                ),
                DerpConnInfoValidator(
                    exists=True,
                    servers=DERP_SERVERS_STRS,
                ),
                NatTraversalConnInfoValidator(
                    alpha.public_key,
                    beta.public_key,
                    False,
                    does_not_contain=["0:0:0:0:0:0"],
                    count=1,
                ),
            ])
        )
        beta_validator = (
            EventValidator.new_with_basic_validators(BETA_FINGERPRINT)
            .add_rtt_validators([alpha_ip_stack, beta_ip_stack, None])
            .add_validator_list([
                ExternalLinksValidator(exists=False),
                ConnectivityMatrixValidator(
                    exists=True,
                    no_of_connections=1,
                    all_connections_up=False,
                    expected_states=[(
                        DERP_BIT
                        | WG_BIT
                        | ip_stack_to_bits(
                            testing.unpack_optional(
                                choose_peer_stack(beta_ip_stack, alpha_ip_stack)
                            )
                        )
                    )],
                ),
                MembersValidator(
                    exists=True,
                    contains=[ALPHA_FINGERPRINT, BETA_FINGERPRINT],
                ),
                SentDataValidator(
                    exists=True,
                    members=[ALPHA_FINGERPRINT],
                    does_not_contain=["0:0:0:0:0"],
                ),
                ReceivedDataValidator(
                    exists=True,
                    members=[ALPHA_FINGERPRINT],
                    does_not_contain=["0:0:0:0:0"],
                ),
                DerpConnInfoValidator(
                    exists=True,
                    servers=DERP_SERVERS_STRS,
                ),
                NatTraversalConnInfoValidator(
                    beta.public_key,
                    alpha.public_key,
                    False,
                    does_not_contain=["0:0:0:0:0:0"],
                    count=1,
                ),
            ])
        )

        if COLLECT_NAT_TYPE:
            alpha_validator.add_validator_list([
                SelfNatTypeValidator("PortRestrictedCone"),
                MembersNatTypeValidator([]),
            ])
            beta_validator.add_validator_list([
                SelfNatTypeValidator("PortRestrictedCone"),
                MembersNatTypeValidator([]),
            ])

        res = alpha_validator.validate(alpha_events[0])
        assert res[0], res[1]
        res = beta_validator.validate(beta_events[0])
        assert res[0], res[1]

        # Validate all nodes have the same meshnet id
        assert alpha_events[0].fp == beta_events[0].fp

        assert await alpha_conn_tracker.get_out_of_limits() is None
        assert await beta_conn_tracker.get_out_of_limits() is None

        # LLT-5532: To be cleaned up...
        client_alpha.allow_errors(
            ["telio_proxy::proxy.*Unable to send. WG Address not available"]
        )
        client_beta.allow_errors(
            ["telio_proxy::proxy.*Unable to send. WG Address not available"]
        )


@pytest.mark.moose
@pytest.mark.asyncio
@pytest.mark.parametrize("alpha_ip_stack,beta_ip_stack", IP_STACK_TEST_CONFIGS)
async def test_lana_with_disconnected_node(
    alpha_ip_stack: IPStack, beta_ip_stack: IPStack
) -> None:
    async with AsyncExitStack() as exit_stack:
        api = API()
        (alpha, beta) = api.default_config_two_nodes(
            True, True, alpha_ip_stack=alpha_ip_stack, beta_ip_stack=beta_ip_stack
        )
        (connection_alpha, alpha_conn_tracker) = await exit_stack.enter_async_context(
            new_connection_with_conn_tracker(
                ConnectionTag.DOCKER_CONE_CLIENT_1,
                generate_connection_tracker_config(
                    ConnectionTag.DOCKER_CONE_CLIENT_1,
                    derp_1_limits=ConnectionLimits(1, 1),
                    ping_limits=ConnectionLimits(None, None),
                    ping6_limits=ConnectionLimits(None, None),
                ),
            )
        )
        (connection_beta, beta_conn_tracker) = await exit_stack.enter_async_context(
            new_connection_with_conn_tracker(
                ConnectionTag.DOCKER_CONE_CLIENT_2,
                generate_connection_tracker_config(
                    ConnectionTag.DOCKER_CONE_CLIENT_2,
                    derp_1_limits=ConnectionLimits(1, 1),
                    ping_limits=ConnectionLimits(None, None),
                    ping6_limits=ConnectionLimits(None, None),
                ),
            )
        )

        await add_5ms_delay_to_connections(
            exit_stack, [connection_alpha, connection_beta]
        )

        await clean_container(connection_alpha)
        await clean_container(connection_beta)

        # In this test, we'll manually trigger the collection of QoS
        def get_features_with_long_qos() -> Features:
            features = build_telio_features()
            assert features.nurse is not None
            assert features.nurse.qos is not None
            features.nurse.qos.rtt_interval = RTT_INTERVAL * 10
            return features

        client_alpha, client_beta = await start_alpha_beta_in_relay(
            exit_stack,
            api,
            alpha,
            beta,
            connection_alpha,
            connection_beta,
            get_features_with_long_qos(),
            get_features_with_long_qos(),
        )

        await asyncio.gather(
            client_alpha.wait_for_state_on_any_derp([RelayState.CONNECTED]),
            client_beta.wait_for_state_on_any_derp([RelayState.CONNECTED]),
        )
        await asyncio.gather(
            client_alpha.wait_for_state_peer(
                beta.public_key, [NodeState.CONNECTED], [PathType.DIRECT]
            ),
            client_beta.wait_for_state_peer(
                alpha.public_key, [NodeState.CONNECTED], [PathType.DIRECT]
            ),
        )

        await client_alpha.trigger_qos_collection()
        await client_beta.trigger_qos_collection()

        await ping_node(connection_alpha, alpha, beta)

        await asyncio.sleep(DEFAULT_WAITING_TIME)

        await client_alpha.trigger_event_collection()
        await client_beta.trigger_event_collection()

        alpha_events = await wait_for_event_dump(
            ConnectionTag.DOCKER_CONE_CLIENT_1, ALPHA_EVENTS_PATH, nr_events=1
        )
        beta_events = await wait_for_event_dump(
            ConnectionTag.DOCKER_CONE_CLIENT_2, BETA_EVENTS_PATH, nr_events=1
        )
        assert alpha_events
        assert beta_events

        if base64.b64decode(alpha.public_key) < base64.b64decode(beta.public_key):
            reporting_connection = connection_alpha
            losing_key = beta.public_key
        else:
            reporting_connection = connection_beta
            losing_key = alpha.public_key

        async with TelioLogNotifier(reporting_connection).run() as telio_log_notifier:
            if losing_key == beta.public_key:
                relayed_state_reported = telio_log_notifier.notify_output(
                    f'Relayed peer state change for "{losing_key[:4]}...{losing_key[-4:]}" to Connected will be reported'
                )

            # disconnect beta and trigger analytics on alpha
            await client_beta.stop_device()

            if losing_key == beta.public_key:
                await relayed_state_reported.wait()

        beta_events = await wait_for_event_dump(
            ConnectionTag.DOCKER_CONE_CLIENT_2, BETA_EVENTS_PATH, nr_events=2
        )
        assert beta_events

        # Trigger QoS on disconnected node. All ICMPs should timeout
        await asyncio.sleep(DEFAULT_WAITING_TIME)
        await client_alpha.trigger_qos_collection()
        await asyncio.sleep(DEFAULT_WAITING_TIME)

        await client_alpha.trigger_event_collection()
        alpha_events = await wait_for_event_dump(
            ConnectionTag.DOCKER_CONE_CLIENT_1, ALPHA_EVENTS_PATH, nr_events=2
        )
        assert alpha_events

        alpha_validator = (
            EventValidator.new_with_basic_validators(ALPHA_FINGERPRINT)
            .add_rtt_validators([alpha_ip_stack, beta_ip_stack, None])
            .add_validator_list([
                ExternalLinksValidator(exists=False),
                ConnectivityMatrixValidator(
                    exists=True,
                    no_of_connections=1,
                    all_connections_up=False,
                    expected_states=[(
                        DERP_BIT
                        | WG_BIT
                        | ip_stack_to_bits(
                            testing.unpack_optional(
                                choose_peer_stack(alpha_ip_stack, beta_ip_stack)
                            )
                        )
                    )],
                ),
                MembersValidator(
                    exists=True,
                    contains=[ALPHA_FINGERPRINT, BETA_FINGERPRINT],
                ),
                SentDataValidator(
                    exists=True,
                    members=[BETA_FINGERPRINT],
                    does_not_contain=["0:0:0:0:0"],
                ),
                ReceivedDataValidator(
                    exists=True,
                    members=[BETA_FINGERPRINT],
                    does_not_contain=["0:0:0:0:0"],
                ),
                DerpConnInfoValidator(
                    exists=True,
                    servers=DERP_SERVERS_STRS,
                ),
                NatTraversalConnInfoValidator(
                    alpha.public_key,
                    beta.public_key,
                    False,
                    does_not_contain=["0:0:0:0:0:0"],
                    count=1,
                ),
            ])
        )

        beta_validator = (
            EventValidator.new_with_basic_validators(BETA_FINGERPRINT)
            .add_rtt_validators([alpha_ip_stack, beta_ip_stack, None])
            .add_validator_list([
                ExternalLinksValidator(exists=False),
                ConnectivityMatrixValidator(
                    exists=True,
                    no_of_connections=1,
                    all_connections_up=False,
                    expected_states=[(
                        DERP_BIT
                        | WG_BIT
                        | ip_stack_to_bits(
                            testing.unpack_optional(
                                choose_peer_stack(beta_ip_stack, alpha_ip_stack)
                            )
                        )
                    )],
                ),
                MembersValidator(
                    exists=True,
                    contains=[ALPHA_FINGERPRINT, BETA_FINGERPRINT],
                ),
                SentDataValidator(
                    exists=True,
                    members=[ALPHA_FINGERPRINT],
                    does_not_contain=["0:0:0:0:0"],
                ),
                ReceivedDataValidator(
                    exists=True,
                    members=[ALPHA_FINGERPRINT],
                    does_not_contain=["0:0:0:0:0"],
                ),
                DerpConnInfoValidator(
                    exists=True,
                    servers=DERP_SERVERS_STRS,
                ),
                NatTraversalConnInfoValidator(
                    beta.public_key,
                    alpha.public_key,
                    False,
                    does_not_contain=["0:0:0:0:0:0"],
                    count=1,
                ),
            ])
        )

        if COLLECT_NAT_TYPE:
            alpha_validator.add_validator(SelfNatTypeValidator("PortRestrictedCone"))
            beta_validator.add_validator(SelfNatTypeValidator("PortRestrictedCone"))

        res = alpha_validator.validate(alpha_events[0])
        assert res[0], res[1]
        res = beta_validator.validate(beta_events[0])
        assert res[0], res[1]

        # Connectivity matrix is not persistent, will be missing when peer is offline
        alpha_validator = EventValidator.new_with_basic_validators(
            ALPHA_FINGERPRINT
        ).add_validator_list([
            ExternalLinksValidator(exists=False),
            ConnectivityMatrixValidator(exists=False),
            MembersValidator(
                exists=True,
                contains=[ALPHA_FINGERPRINT, BETA_FINGERPRINT],
            ),
            SentDataValidator(
                exists=True,
                members=[BETA_FINGERPRINT],
                does_not_contain=["0:0:0:0:0"],
            ),
            ReceivedDataValidator(
                exists=True,
                members=[BETA_FINGERPRINT],
            ),
            DerpConnInfoValidator(
                exists=False,
            ),
            NatTraversalConnInfoValidator(
                alpha.public_key,
                beta.public_key,
                False,
                does_not_contain=["0:0:0:0:0:0"],
                count=1,
            ),
        ])

        (
            rtt_c,
            rtt_dnc,
            rtt_loss_c,
            rtt_loss_dnc,
            rtt6_c,
            rtt6_dnc,
            rtt6_loss_c,
            rtt6_loss_dnc,
        ) = (None, None, None, None, None, None, None, None)
        rtt_eq, rtt_loss_eq, rtt6_eq, rtt6_loss_eq = "", "", "", ""
        match connectivity_stack(alpha_ip_stack, beta_ip_stack):
            case IPStack.IPv4:
                # IPv4 only
                rtt_c = ["0:0:0:0:0"]
                rtt_dnc = ["null:null:null:null:null"]
                rtt_loss_c = ["100:100:100:100:100"]
                rtt_loss_dnc = ["null:null:null:null:null", "0:0:0:0:0"]
                rtt6_c = ["null:null:null:null:null"]
                rtt6_dnc = ["0:0:0:0:0"]
                rtt6_loss_c = ["null:null:null:null:null"]
                rtt6_loss_dnc = ["0:0:0:0:0", "100:100:100:100:100"]
            case None:
                assert False, "No IP stack"
            case IPStack.IPv6:
                # IPv6 only
                rtt_c = ["null:null:null:null:null"]
                rtt_dnc = ["0:0:0:0:0"]
                rtt_loss_c = ["null:null:null:null:null"]
                rtt_loss_dnc = ["0:0:0:0:0", "100:100:100:100:100"]
                rtt6_c = ["0:0:0:0:0"]
                rtt6_dnc = ["null:null:null:null:null"]
                rtt6_loss_c = ["100:100:100:100:100"]
                rtt6_loss_dnc = ["null:null:null:null:null", "0:0:0:0:0"]
            case IPStack.IPv4v6:
                # IPv4 and IPv6
                rtt_c = ["0:0:0:0:0"]
                rtt_dnc = ["null:null:null:null:null"]
                rtt_loss_c = ["100:100:100:100:100"]
                rtt_loss_dnc = ["null:null:null:null:null", "0:0:0:0:0"]
                rtt6_c = ["0:0:0:0:0"]
                rtt6_dnc = ["null:null:null:null:null"]
                rtt6_loss_c = ["100:100:100:100:100"]
                rtt6_loss_dnc = ["null:null:null:null:null", "0:0:0:0:0"]

        alpha_validator.add_validator_list([
            RttValidator(
                exists=True,
                members=[BETA_FINGERPRINT],
                does_not_contain=rtt_dnc,
                contains=rtt_c,
                equals=rtt_eq,
            ),
            RttLossValidator(
                exists=True,
                members=[BETA_FINGERPRINT],
                does_not_contain=rtt_loss_dnc,
                contains=rtt_loss_c,
                equals=rtt_loss_eq,
            ),
            Rtt6Validator(
                exists=True,
                members=[BETA_FINGERPRINT],
                does_not_contain=rtt6_dnc,
                contains=rtt6_c,
                equals=rtt6_eq,
            ),
            Rtt6LossValidator(
                exists=True,
                members=[BETA_FINGERPRINT],
                does_not_contain=rtt6_loss_dnc,
                contains=rtt6_loss_c,
                equals=rtt6_loss_eq,
            ),
        ])

        res = alpha_validator.validate(alpha_events[1])
        assert res[0], res[1]

        beta_validator = EventValidator(BETA_FINGERPRINT).add_validator_list([
            NameValidator("disconnect"),
            CategoryValidator("service_quality"),
            FingerprintValidator(exists=True),
            ExternalLinksValidator(exists=False),
            ConnectivityMatrixValidator(
                exists=True,
                no_of_connections=1,
                all_connections_up=False,
                expected_states=[(
                    DERP_BIT
                    | WG_BIT
                    | ip_stack_to_bits(
                        testing.unpack_optional(
                            choose_peer_stack(beta_ip_stack, alpha_ip_stack)
                        )
                    )
                )],
            ),
            MembersValidator(
                exists=True,
                contains=[ALPHA_FINGERPRINT, BETA_FINGERPRINT],
            ),
            SentDataValidator(exists=False),
            ReceivedDataValidator(exists=False),
            DerpConnInfoValidator(
                exists=True,
                servers=DERP_SERVERS_STRS,
            ),
            NatTraversalConnInfoValidator(
                beta.public_key,
                alpha.public_key,
                False,
                does_not_contain=["0:0:0:0:0:0"],
                count=1,
            ),
            RttValidator(
                exists=False,
            ),
            RttLossValidator(
                exists=False,
            ),
            Rtt6Validator(
                exists=False,
            ),
            Rtt6LossValidator(
                exists=False,
            ),
        ])

        res = alpha_validator.validate(alpha_events[1])
        assert res[0], res[1]
        res = beta_validator.validate(beta_events[1])
        assert res[0], res[1]

        # Validate all nodes have the same meshnet id
        assert (
            alpha_events[0].fp
            == alpha_events[1].fp
            == beta_events[0].fp
            == beta_events[1].fp
        )
        assert await alpha_conn_tracker.get_out_of_limits() is None
        assert await beta_conn_tracker.get_out_of_limits() is None


@pytest.mark.moose
@pytest.mark.asyncio
@pytest.mark.parametrize("alpha_ip_stack,beta_ip_stack", IP_STACK_TEST_CONFIGS)
async def test_lana_with_second_node_joining_later_meshnet_id_can_change(
    alpha_ip_stack: IPStack, beta_ip_stack: IPStack
) -> None:
    async with AsyncExitStack() as exit_stack:
        api = API()
        beta = api.default_config_one_node(True, ip_stack=beta_ip_stack)
        (connection_beta, beta_conn_tracker) = await exit_stack.enter_async_context(
            new_connection_with_conn_tracker(
                ConnectionTag.DOCKER_CONE_CLIENT_2,
                generate_connection_tracker_config(
                    ConnectionTag.DOCKER_CONE_CLIENT_2,
                    derp_1_limits=ConnectionLimits(1, None),
                ),
            )
        )
        await clean_container(connection_beta)

        client_beta = await exit_stack.enter_async_context(
            telio.Client(
                connection_beta,
                beta,
                telio_features=build_telio_features(),
                fingerprint=BETA_FINGERPRINT,
            ).run(api.get_meshnet_config(beta.id))
        )

        await client_beta.trigger_event_collection()
        beta_events = await wait_for_event_dump(
            ConnectionTag.DOCKER_CONE_CLIENT_2, BETA_EVENTS_PATH, nr_events=1
        )
        assert beta_events

        alpha = api.default_config_one_node(True, ip_stack=alpha_ip_stack)
        (connection_alpha, alpha_conn_tracker) = await exit_stack.enter_async_context(
            new_connection_with_conn_tracker(
                ConnectionTag.DOCKER_CONE_CLIENT_1,
                generate_connection_tracker_config(
                    ConnectionTag.DOCKER_CONE_CLIENT_1,
                    derp_1_limits=ConnectionLimits(1, 1),
                ),
            )
        )
        await clean_container(connection_alpha)

        alpha.set_peer_firewall_settings(beta.id, allow_incoming_connections=True)
        client_alpha = await exit_stack.enter_async_context(
            telio.Client(
                connection_alpha,
                alpha,
                telio_features=build_telio_features(),
                fingerprint=ALPHA_FINGERPRINT,
            ).run(api.get_meshnet_config(alpha.id))
        )

        beta.set_peer_firewall_settings(alpha.id, allow_incoming_connections=True)
        await client_beta.set_meshnet_config(api.get_meshnet_config(beta.id))

        await asyncio.gather(
            client_alpha.wait_for_state_peer(
                beta.public_key, [NodeState.CONNECTED], [PathType.DIRECT]
            ),
            client_beta.wait_for_state_peer(
                alpha.public_key, [NodeState.CONNECTED], [PathType.DIRECT]
            ),
        )

        await ping_node(connection_alpha, alpha, beta)
        await ping_node(connection_beta, beta, alpha)

        await client_alpha.trigger_event_collection()
        await client_beta.trigger_event_collection()

        alpha_events = await wait_for_event_dump(
            ConnectionTag.DOCKER_CONE_CLIENT_1, ALPHA_EVENTS_PATH, nr_events=1
        )
        beta_events = await wait_for_event_dump(
            ConnectionTag.DOCKER_CONE_CLIENT_2, BETA_EVENTS_PATH, nr_events=2
        )
        assert alpha_events
        assert beta_events

        if base64.b64decode(alpha.public_key) < base64.b64decode(beta.public_key):
            assert alpha_events[0].fp == beta_events[1].fp != beta_events[0].fp
        elif base64.b64decode(alpha.public_key) > base64.b64decode(beta.public_key):
            assert alpha_events[0].fp == beta_events[1].fp == beta_events[0].fp
        else:
            assert False, "[PANIC] Public keys match!"

        assert await alpha_conn_tracker.get_out_of_limits() is None
        assert await beta_conn_tracker.get_out_of_limits() is None

        # LLT-5532: To be cleaned up...
        client_alpha.allow_errors(
            ["telio_proxy::proxy.*Unable to send. WG Address not available"]
        )
        client_beta.allow_errors(
            ["telio_proxy::proxy.*Unable to send. WG Address not available"]
        )


@pytest.mark.moose
@pytest.mark.asyncio
@pytest.mark.parametrize("alpha_ip_stack,beta_ip_stack", IP_STACK_TEST_CONFIGS)
async def test_lana_same_meshnet_id_is_reported_after_a_restart(
    alpha_ip_stack: IPStack, beta_ip_stack: IPStack
):
    async with AsyncExitStack() as exit_stack:
        api = API()
        beta = api.default_config_one_node(True, ip_stack=beta_ip_stack)
        connection_beta = await exit_stack.enter_async_context(
            new_connection_by_tag(ConnectionTag.DOCKER_CONE_CLIENT_2)
        )
        await clean_container(connection_beta)

        async with telio.Client(
            connection_beta,
            beta,
            telio_features=build_telio_features(),
            fingerprint=BETA_FINGERPRINT,
        ).run(api.get_meshnet_config(beta.id)) as client_beta:

            await client_beta.trigger_event_collection()
            beta_events = await wait_for_event_dump(
                ConnectionTag.DOCKER_CONE_CLIENT_2, BETA_EVENTS_PATH, nr_events=1
            )
            assert beta_events
            initial_beta_meshnet_id = beta_events[0].fp

            api.remove(beta.id)

        beta = api.default_config_one_node(True, ip_stack=alpha_ip_stack)
        connection_beta = await exit_stack.enter_async_context(
            new_connection_by_tag(ConnectionTag.DOCKER_CONE_CLIENT_2)
        )

        client_beta = await exit_stack.enter_async_context(
            telio.Client(
                connection_beta,
                beta,
                telio_features=build_telio_features(),
                fingerprint=BETA_FINGERPRINT,
            ).run(api.get_meshnet_config(beta.id))
        )

        await client_beta.trigger_event_collection()
        beta_events = await wait_for_event_dump(
            ConnectionTag.DOCKER_CONE_CLIENT_2, BETA_EVENTS_PATH, nr_events=3
        )
        assert beta_events
        second_beta_meshnet_id = beta_events[2].fp

        assert initial_beta_meshnet_id == second_beta_meshnet_id


@pytest.mark.moose
@pytest.mark.asyncio
@pytest.mark.parametrize(
    "initial_heartbeat_interval", [pytest.param(5), pytest.param(300)]
)
async def test_lana_initial_heartbeat_no_trigger(
    initial_heartbeat_interval: int,
):
    async with AsyncExitStack() as exit_stack:
        api = API()
        alpha = api.default_config_one_node(True)

        connection_alpha = await exit_stack.enter_async_context(
            new_connection_by_tag(ConnectionTag.DOCKER_CONE_CLIENT_1)
        )
        await clean_container(connection_alpha)

        await exit_stack.enter_async_context(
            telio.Client(
                connection_alpha,
                alpha,
                telio_features=build_telio_features(
                    initial_heartbeat_interval=initial_heartbeat_interval,
                ),
                fingerprint=ALPHA_FINGERPRINT,
            ).run(api.get_meshnet_config(alpha.id))
        )

        if initial_heartbeat_interval == 5:
            await asyncio.sleep(initial_heartbeat_interval)
            assert await wait_for_event_dump(
                ConnectionTag.DOCKER_CONE_CLIENT_1, ALPHA_EVENTS_PATH, nr_events=1
            )
        else:
            assert not await wait_for_event_dump(
                ConnectionTag.DOCKER_CONE_CLIENT_1, ALPHA_EVENTS_PATH, nr_events=1
            )
