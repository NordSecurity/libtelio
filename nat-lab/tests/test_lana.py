# pylint: disable=too-many-lines

import asyncio
import base64
import os
import pytest
from contextlib import AsyncExitStack
from pathlib import Path
from tests.config import (
    WG_SERVER,
    STUN_SERVER,
    STUNV6_SERVER,
    DERP_PRIMARY,
    DERP_SECONDARY,
    DERP_TERTIARY,
)
from tests.helpers import connectivity_stack
from tests.log_collector import copy_file, find_files, get_log_without_flush
from tests.mesh_api import API, Node
from tests.telio import Client
from tests.utils import testing, stun
from tests.utils.analytics import (
    fetch_moose_events,
    DERP_BIT,
    Event,
    WG_BIT,
    IPV4_BIT,
    IPV6_BIT,
)
from tests.utils.analytics.event_validator import (
    CategoryValidator,
    ConnectivityMatrixValidator,
    DerpConnInfoValidator,
    ExternalLinksValidator,
    EventValidator,
    FingerprintValidator,
    MembersValidator,
    NameValidator,
    NatTraversalConnInfoValidator,
    ReceivedDataValidator,
    RttValidator,
    RttLossValidator,
    Rtt6LossValidator,
    Rtt6Validator,
    SentDataValidator,
    ALPHA_FINGERPRINT,
    BETA_FINGERPRINT,
    GAMMA_FINGERPRINT,
    NODES_FINGERPRINTS,
)
from tests.utils.bindings import (
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
from tests.utils.connection import Connection, ConnectionTag
from tests.utils.connection_util import (
    generate_connection_tracker_config,
    new_connection_with_conn_tracker,
    new_connection_by_tag,
    add_outgoing_packets_delay,
)
from tests.utils.logger import log
from tests.utils.moose import MOOSE_DB_TIMEOUT_MS, MOOSE_LOGS_DIR
from tests.utils.ping import ping
from tests.utils.router import IPStack, IPProto
from tests.utils.telio_log_notifier import TelioLogNotifier
from tests.utils.testing import get_current_test_log_path
from typing import List, Optional

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
RTT_INTERVAL = 3 * 60

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


def build_telio_features(
    initial_heartbeat_interval: int = 300,
    rtt_interval: int = RTT_INTERVAL,
    exclude_ip_range_check: Optional[str] = None,
) -> Features:
    features = default_features(
        enable_lana=(CONTAINER_EVENT_PATH, False),
        enable_direct=True,
        enable_nurse=True,
        enable_firewall_exclusion_range=exclude_ip_range_check,
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
        rtt_interval=rtt_interval,
        buckets=5,
        rtt_tries=1,
    )
    return features


async def clean_container(connection: Connection):
    await connection.create_process(
        ["rm", "-f", CONTAINER_EVENT_PATH], quiet=True
    ).execute()
    await connection.create_process(
        ["rm", "-f", CONTAINER_EVENT_BACKUP_PATH], quiet=True
    ).execute()
    await connection.create_process(
        ["rm", "-f", CONTAINER_EVENT_PATH + "-journal"], quiet=True
    ).execute()


async def get_moose_db_file(
    connection: Connection,
    container_path: str,
    container_backup_path: str,
    local_path: str,
) -> None:
    Path(local_path).unlink(missing_ok=True)
    max_retries = MOOSE_DB_TIMEOUT_MS / 1000
    max_timeout = MOOSE_DB_TIMEOUT_MS / 30

    while max_retries:
        try:
            await connection.create_process(
                [
                    "sqlite3",
                    container_path,
                    "--cmd",
                    f"PRAGMA busy_timeout = {max_timeout};",
                    f".backup {container_backup_path}",
                ],
                quiet=True,
            ).execute(privileged=True)

            await connection.download(container_backup_path, local_path)
            return
        except Exception as e:  # pylint: disable=broad-exception-caught
            print(f"get_moose_db_file error: {e}, retrying ...")
            max_retries -= 1
            await asyncio.sleep(0.1)
    if not max_retries:
        raise Exception("Retries exhausted, while trying to fetch moose db file")


async def wait_for_event_dump(
    connection: Connection,
    events_path: str,
    nr_events: int,
    timeout: int = DEFAULT_CHECK_TIMEOUT,
) -> Optional[list[Event]]:
    start_time = asyncio.get_event_loop().time()
    events = []
    while asyncio.get_event_loop().time() - start_time < timeout:
        await get_moose_db_file(
            connection, CONTAINER_EVENT_PATH, CONTAINER_EVENT_BACKUP_PATH, events_path
        )
        events = fetch_moose_events(events_path)
        if len(events) == nr_events:
            log.info(
                "Found db from %s with the expected %s events.",
                connection.tag.name,
                nr_events,
            )
            return events
        await asyncio.sleep(DEFAULT_CHECK_INTERVAL)
    log.warning(
        "Failed looking db from %s, expected %s but %s were found.",
        connection.tag.name,
        nr_events,
        len(events),
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
) -> tuple[Client, Client]:
    client_alpha = await exit_stack.enter_async_context(
        Client(
            connection_alpha,
            alpha,
            telio_features=alpha_features,
            fingerprint=ALPHA_FINGERPRINT,
        ).run(api.get_meshnet_config(alpha.id))
    )

    client_beta = Client(
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
                derp_1_limits=(1, 1),
                vpn_1_limits=(1 if alpha_has_vpn_connection else 0, 1),
            ),
        )
    )
    (connection_beta, beta_conn_tracker) = await exit_stack.enter_async_context(
        new_connection_with_conn_tracker(
            ConnectionTag.DOCKER_CONE_CLIENT_2,
            generate_connection_tracker_config(
                ConnectionTag.DOCKER_CONE_CLIENT_2,
                derp_1_limits=(1, 1),
                vpn_1_limits=(1 if beta_has_vpn_connection else 0, 1),
            ),
        )
    )
    (connection_gamma, gamma_conn_tracker) = await exit_stack.enter_async_context(
        new_connection_with_conn_tracker(
            ConnectionTag.DOCKER_SYMMETRIC_CLIENT_1,
            generate_connection_tracker_config(
                ConnectionTag.DOCKER_SYMMETRIC_CLIENT_1,
                derp_1_limits=(1, 1),
                vpn_1_limits=(1 if gamma_has_vpn_connection else 0, 1),
            ),
        )
    )

    await api.prepare_vpn_servers()

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
        Client(
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

    await client_alpha.trigger_qos_collection()
    await client_beta.trigger_qos_collection()
    await client_gamma.trigger_qos_collection()

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
        connection_alpha, ALPHA_EVENTS_PATH, nr_events=1
    )
    assert alpha_events
    beta_events = await wait_for_event_dump(
        connection_beta, BETA_EVENTS_PATH, nr_events=1
    )
    assert beta_events
    gamma_events = await wait_for_event_dump(
        connection_gamma, GAMMA_EVENTS_PATH, nr_events=1
    )
    assert gamma_events

    assert await alpha_conn_tracker.find_conntracker_violations() is None
    assert await beta_conn_tracker.find_conntracker_violations() is None
    assert await gamma_conn_tracker.find_conntracker_violations() is None

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
            True,
            True,
            alpha_ip_stack=alpha_ip_stack,
            beta_ip_stack=beta_ip_stack,
            allow_peer_traffic_routing=True,
        )
        (connection_alpha, alpha_conn_tracker) = await exit_stack.enter_async_context(
            new_connection_with_conn_tracker(
                ConnectionTag.DOCKER_CONE_CLIENT_1,
                generate_connection_tracker_config(
                    ConnectionTag.DOCKER_CONE_CLIENT_1,
                    derp_1_limits=(1, 1),
                ),
            )
        )

        (connection_beta, beta_conn_tracker) = await exit_stack.enter_async_context(
            new_connection_with_conn_tracker(
                ConnectionTag.DOCKER_OPEN_INTERNET_CLIENT_DUAL_STACK,
                generate_connection_tracker_config(
                    ConnectionTag.DOCKER_OPEN_INTERNET_CLIENT_DUAL_STACK,
                    derp_1_limits=(1, 1),
                    stun6_limits=((1, 1) if is_stun6_needed else (0, 0)),
                    stun_limits=((1, 1) if not is_stun6_needed else (0, 0)),
                    ping_limits=(None, None),
                    ping6_limits=(None, None),
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
            build_telio_features(exclude_ip_range_check="10.0.0.0/8"),
            build_telio_features(exclude_ip_range_check="10.0.0.0/8"),
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

        await client_alpha.trigger_qos_collection()
        await client_beta.trigger_qos_collection()

        await asyncio.sleep(DEFAULT_WAITING_TIME)

        await client_alpha.trigger_event_collection()
        await client_beta.trigger_event_collection()

        alpha_events = await wait_for_event_dump(
            connection_alpha, ALPHA_EVENTS_PATH, nr_events=1
        )
        beta_events = await wait_for_event_dump(
            connection_beta,
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

        res = alpha_validator.validate(alpha_events[0])
        assert res[0], res[1]
        res = beta_validator.validate(beta_events[0])
        assert res[0], res[1]

        # Validate all nodes have the same meshnet id
        assert alpha_events[0].fp == beta_events[0].fp

        assert await alpha_conn_tracker.find_conntracker_violations() is None
        assert await beta_conn_tracker.find_conntracker_violations() is None

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
                    derp_1_limits=(1, 1),
                    ping_limits=(None, None),
                    ping6_limits=(None, None),
                ),
            )
        )
        (connection_beta, beta_conn_tracker) = await exit_stack.enter_async_context(
            new_connection_with_conn_tracker(
                ConnectionTag.DOCKER_CONE_CLIENT_2,
                generate_connection_tracker_config(
                    ConnectionTag.DOCKER_CONE_CLIENT_2,
                    derp_1_limits=(1, 1),
                    ping_limits=(None, None),
                    ping6_limits=(None, None),
                ),
            )
        )

        await add_5ms_delay_to_connections(
            exit_stack, [connection_alpha, connection_beta]
        )

        await clean_container(connection_alpha)
        await clean_container(connection_beta)

        features = build_telio_features()
        assert features.nurse is not None
        assert features.nurse.qos is not None

        client_alpha, client_beta = await start_alpha_beta_in_relay(
            exit_stack,
            api,
            alpha,
            beta,
            connection_alpha,
            connection_beta,
            features,
            features,
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
            connection_alpha, ALPHA_EVENTS_PATH, nr_events=1
        )
        beta_events = await wait_for_event_dump(
            connection_beta, BETA_EVENTS_PATH, nr_events=1
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
            relayed_state_reported = telio_log_notifier.notify_output(
                f'Relayed peer state change for "{losing_key[:4]}...{losing_key[-4:]}" to Connected will be reported'
            )

            # disconnect beta and trigger analytics on alpha
            await client_beta.stop_device()

            if losing_key == beta.public_key:
                await relayed_state_reported.wait()

        beta_events = await wait_for_event_dump(
            connection_beta, BETA_EVENTS_PATH, nr_events=2
        )
        assert beta_events

        # Trigger QoS on disconnected node. All ICMPs should timeout
        await asyncio.sleep(DEFAULT_WAITING_TIME)
        await client_alpha.trigger_qos_collection()
        await asyncio.sleep(DEFAULT_WAITING_TIME)

        await client_alpha.trigger_event_collection()
        alpha_events = await wait_for_event_dump(
            connection_alpha, ALPHA_EVENTS_PATH, nr_events=2
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
        assert await alpha_conn_tracker.find_conntracker_violations() is None
        assert await beta_conn_tracker.find_conntracker_violations() is None


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
                    derp_1_limits=(1, None),
                ),
            )
        )
        await clean_container(connection_beta)

        client_beta = await exit_stack.enter_async_context(
            Client(
                connection_beta,
                beta,
                telio_features=build_telio_features(),
                fingerprint=BETA_FINGERPRINT,
            ).run(api.get_meshnet_config(beta.id))
        )

        await client_beta.trigger_event_collection()
        beta_events = await wait_for_event_dump(
            connection_beta, BETA_EVENTS_PATH, nr_events=1
        )
        assert beta_events

        alpha = api.default_config_one_node(True, ip_stack=alpha_ip_stack)
        (connection_alpha, alpha_conn_tracker) = await exit_stack.enter_async_context(
            new_connection_with_conn_tracker(
                ConnectionTag.DOCKER_CONE_CLIENT_1,
                generate_connection_tracker_config(
                    ConnectionTag.DOCKER_CONE_CLIENT_1,
                    derp_1_limits=(1, 1),
                ),
            )
        )
        await clean_container(connection_alpha)

        alpha.set_peer_firewall_settings(beta.id, allow_incoming_connections=True)
        client_alpha = await exit_stack.enter_async_context(
            Client(
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
            connection_alpha, ALPHA_EVENTS_PATH, nr_events=1
        )
        beta_events = await wait_for_event_dump(
            connection_beta, BETA_EVENTS_PATH, nr_events=2
        )
        assert alpha_events
        assert beta_events

        if base64.b64decode(alpha.public_key) < base64.b64decode(beta.public_key):
            assert alpha_events[0].fp == beta_events[1].fp != beta_events[0].fp
        elif base64.b64decode(alpha.public_key) > base64.b64decode(beta.public_key):
            assert alpha_events[0].fp == beta_events[1].fp == beta_events[0].fp
        else:
            assert False, "[PANIC] Public keys match!"

        assert await alpha_conn_tracker.find_conntracker_violations() is None
        assert await beta_conn_tracker.find_conntracker_violations() is None

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

        async with Client(
            connection_beta,
            beta,
            telio_features=build_telio_features(),
            fingerprint=BETA_FINGERPRINT,
        ).run(api.get_meshnet_config(beta.id)) as client_beta:

            await client_beta.trigger_event_collection()
            beta_events = await wait_for_event_dump(
                connection_beta, BETA_EVENTS_PATH, nr_events=1
            )
            assert beta_events
            initial_beta_meshnet_id = beta_events[0].fp

            api.remove(beta.id)
        if os.environ.get("NATLAB_SAVE_LOGS") is not None:
            log_content = await get_log_without_flush(connection_beta)
            log_dir = get_current_test_log_path()
            os.makedirs(log_dir, exist_ok=True)
            path = os.path.join(log_dir, "beta_before_restart.log")
            with open(path, "w", encoding="utf-8") as f:
                f.write(log_content)
            events_path = os.path.join(log_dir, "beta_before_restart.db")
            await get_moose_db_file(
                connection_beta,
                CONTAINER_EVENT_PATH,
                CONTAINER_EVENT_BACKUP_PATH,
                events_path,
            )
            moose_traces = await find_files(
                connection_beta, MOOSE_LOGS_DIR, "moose_trace.log*"
            )
            for trace_path in moose_traces:
                await copy_file(connection_beta, trace_path, log_dir)
                file_name = os.path.basename(trace_path)
                new_file_name = f"beta_before_restart_{file_name}"
                os.rename(
                    os.path.join(log_dir, file_name),
                    os.path.join(log_dir, new_file_name),
                )

        beta = api.default_config_one_node(True, ip_stack=alpha_ip_stack)
        connection_beta = await exit_stack.enter_async_context(
            new_connection_by_tag(ConnectionTag.DOCKER_CONE_CLIENT_2)
        )

        client_beta = await exit_stack.enter_async_context(
            Client(
                connection_beta,
                beta,
                telio_features=build_telio_features(),
                fingerprint=BETA_FINGERPRINT,
            ).run(api.get_meshnet_config(beta.id))
        )

        await client_beta.trigger_event_collection()
        beta_events = await wait_for_event_dump(
            connection_beta, BETA_EVENTS_PATH, nr_events=3
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
            Client(
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
                connection_alpha, ALPHA_EVENTS_PATH, nr_events=1
            )
        else:
            assert not await wait_for_event_dump(
                connection_alpha, ALPHA_EVENTS_PATH, nr_events=1
            )


@pytest.mark.moose
@pytest.mark.asyncio
@pytest.mark.parametrize("initial_heartbeat_interval", [pytest.param(5)])
async def test_lana_initial_heartbeat_count_since_meshnet_start(
    initial_heartbeat_interval: int,
):
    async with AsyncExitStack() as exit_stack:
        api = API()
        alpha = api.default_config_one_node(True)

        connection_alpha = await exit_stack.enter_async_context(
            new_connection_by_tag(ConnectionTag.DOCKER_CONE_CLIENT_1)
        )
        await clean_container(connection_alpha)

        client_alpha = await exit_stack.enter_async_context(
            Client(
                connection_alpha,
                alpha,
                telio_features=build_telio_features(
                    initial_heartbeat_interval=initial_heartbeat_interval,
                ),
                fingerprint=ALPHA_FINGERPRINT,
            ).run()
        )

        await asyncio.sleep(initial_heartbeat_interval + 3)
        assert not await wait_for_event_dump(
            connection_alpha, ALPHA_EVENTS_PATH, nr_events=1
        )

        await client_alpha.set_meshnet_config(api.get_meshnet_config(alpha.id))

        await asyncio.sleep(initial_heartbeat_interval + 3)
        assert await wait_for_event_dump(
            connection_alpha, ALPHA_EVENTS_PATH, nr_events=1
        )


@pytest.mark.moose
@pytest.mark.asyncio
@pytest.mark.parametrize("initial_heartbeat_interval", [pytest.param(5)])
async def test_lana_initial_heartbeat_count_since_meshnet_restart(
    initial_heartbeat_interval: int,
):
    async with AsyncExitStack() as exit_stack:
        api = API()
        alpha = api.default_config_one_node(True)

        connection_alpha = await exit_stack.enter_async_context(
            new_connection_by_tag(ConnectionTag.DOCKER_CONE_CLIENT_1)
        )
        await clean_container(connection_alpha)

        client_alpha = await exit_stack.enter_async_context(
            Client(
                connection_alpha,
                alpha,
                telio_features=build_telio_features(
                    initial_heartbeat_interval=initial_heartbeat_interval,
                ),
                fingerprint=ALPHA_FINGERPRINT,
            ).run()
        )
        await client_alpha.set_meshnet_config(api.get_meshnet_config(alpha.id))

        await asyncio.sleep(initial_heartbeat_interval + 3)
        assert await wait_for_event_dump(
            connection_alpha, ALPHA_EVENTS_PATH, nr_events=1
        )

        await client_alpha.set_mesh_off()
        await client_alpha.set_meshnet_config(api.get_meshnet_config(alpha.id))

        await asyncio.sleep(initial_heartbeat_interval + 3)
        assert await wait_for_event_dump(
            connection_alpha, ALPHA_EVENTS_PATH, nr_events=2
        )


@pytest.mark.moose
@pytest.mark.asyncio
async def test_lana_rtt_interval_controls_periodic_qos_collection():
    async with AsyncExitStack() as exit_stack:
        api = API()

        (alpha, beta) = api.default_config_two_nodes(
            True, True, alpha_ip_stack=IPStack.IPv4v6, beta_ip_stack=IPStack.IPv4v6
        )

        connection_alpha = await exit_stack.enter_async_context(
            new_connection_by_tag(ConnectionTag.DOCKER_CONE_CLIENT_1)
        )
        connection_beta = await exit_stack.enter_async_context(
            new_connection_by_tag(ConnectionTag.DOCKER_CONE_CLIENT_2)
        )

        await clean_container(connection_alpha)
        await clean_container(connection_beta)

        rtt_interval = 30

        telio_features = build_telio_features(rtt_interval=rtt_interval)
        telio_features.direct = None

        client_alpha = await exit_stack.enter_async_context(
            Client(
                connection_alpha,
                alpha,
                telio_features=telio_features,
                fingerprint=ALPHA_FINGERPRINT,
            ).run(api.get_meshnet_config(alpha.id))
        )

        client_beta = await exit_stack.enter_async_context(
            Client(
                connection_beta,
                beta,
                telio_features=telio_features,
                fingerprint=BETA_FINGERPRINT,
            ).run(api.get_meshnet_config(beta.id))
        )

        await asyncio.gather(
            client_alpha.wait_for_state_on_any_derp([RelayState.CONNECTED]),
            client_beta.wait_for_state_on_any_derp([RelayState.CONNECTED]),
        )

        await client_alpha.wait_for_log("Starting periodic ping", count=2)
        await client_beta.wait_for_log("Starting periodic ping", count=2)

        await asyncio.sleep(DEFAULT_WAITING_TIME)

        await client_alpha.trigger_event_collection()
        await client_beta.trigger_event_collection()

        alpha_events = await wait_for_event_dump(
            connection_alpha, ALPHA_EVENTS_PATH, nr_events=1
        )
        beta_events = await wait_for_event_dump(
            connection_beta, BETA_EVENTS_PATH, nr_events=1
        )
        assert alpha_events
        assert beta_events

        alpha_validator = EventValidator.new_with_basic_validators(
            ALPHA_FINGERPRINT
        ).add_rtt_validators([IPStack.IPv4v6, IPStack.IPv4v6])
        beta_validator = EventValidator.new_with_basic_validators(
            BETA_FINGERPRINT
        ).add_rtt_validators([IPStack.IPv4v6, IPStack.IPv4v6])

        res = alpha_validator.validate(alpha_events[0])
        assert res[0], res[1]
        res = beta_validator.validate(beta_events[0])
        assert res[0], res[1]
