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
from mesh_api import API, Node
from telio import PathType
from telio_features import TelioFeatures, Nurse, Lana, Qos, Direct
from typing import List, Optional
from utils import testing, stun
from utils.analytics import (
    fetch_moose_events,
    basic_validator,
    EventValidator,
    DERP_BIT,
    WG_BIT,
    IPV4_BIT,
    IPV6_BIT,
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
from utils.ping import Ping
from utils.router import IPStack, IPProto

CONTAINER_EVENT_PATH = "/event.db"
ALPHA_EVENTS_PATH = "./alpha-events.db"
BETA_EVENTS_PATH = "./beta-events.db"
GAMMA_EVENTS_PATH = "./gamma-events.db"

ALPHA_FINGERPRINT = "alpha_fingerprint"
BETA_FINGERPRINT = "beta_fingerprint"
GAMMA_FINGERPRINT = "gamma_fingerprint"
NODES_FINGERPRINTS = [ALPHA_FINGERPRINT, BETA_FINGERPRINT, GAMMA_FINGERPRINT]

DERP_SERVERS_STRS = [
    f"{DERP_PRIMARY['ipv4']}:{DERP_PRIMARY['relay_port']}",
    f"{DERP_SECONDARY['ipv4']}:{DERP_SECONDARY['relay_port']}",
    f"{DERP_TERTIARY['ipv4']}:{DERP_TERTIARY['relay_port']}",
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


def build_telio_features(
    fingerprint: str, initial_heartbeat_interval: int = 300
) -> TelioFeatures:
    return TelioFeatures(
        lana=Lana(prod=False, event_path=CONTAINER_EVENT_PATH),
        direct=Direct(providers=["stun"]),
        nurse=Nurse(
            fingerprint=fingerprint,
            heartbeat_interval=3600,
            initial_heartbeat_interval=initial_heartbeat_interval,
            qos=Qos(rtt_interval=RTT_INTERVAL, buckets=5, rtt_tries=1),
            enable_nat_type_collection=COLLECT_NAT_TYPE,
            enable_relay_conn_data=True,
            enable_nat_traversal_conn_data=True,
        ),
    )


async def clean_container(connection: Connection):
    await connection.create_process(["rm", "-f", CONTAINER_EVENT_PATH]).execute()
    await connection.create_process(
        ["rm", "-f", CONTAINER_EVENT_PATH + "-journal"]
    ).execute()


def get_moose_db_file(container_tag, container_path, local_path):
    subprocess.run(["rm", "-f", local_path])
    # sqlite3 -bail -batch moose.db "BEGIN EXCLUSIVE TRANSACTION; SELECT 1; ROLLBACK;" > /dev/null
    subprocess.run(
        ["docker", "cp", container_id(container_tag) + ":" + container_path, local_path]
    )


async def wait_for_event_dump(container, events_path, nr_events):
    start_time = asyncio.get_event_loop().time()
    events = []
    while asyncio.get_event_loop().time() - start_time < DEFAULT_CHECK_TIMEOUT:
        get_moose_db_file(container, CONTAINER_EVENT_PATH, events_path)
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

    async with Ping(
        initiator_conn,
        testing.unpack_optional(target.get_ip_address(proto)),
    ).run() as ping:
        await ping.wait_for_next_ping()


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

    client_alpha = await exit_stack.enter_async_context(
        telio.Client(
            connection_alpha,
            alpha,
            telio_features=build_telio_features(ALPHA_FINGERPRINT),
        ).run(api.get_meshmap(alpha.id))
    )

    client_beta = await exit_stack.enter_async_context(
        telio.Client(
            connection_beta,
            beta,
            telio_features=build_telio_features(BETA_FINGERPRINT),
        ).run(api.get_meshmap(beta.id))
    )

    client_gamma = await exit_stack.enter_async_context(
        telio.Client(
            connection_gamma,
            gamma,
            telio_features=build_telio_features(GAMMA_FINGERPRINT),
        ).run(api.get_meshmap(gamma.id))
    )

    await asyncio.gather(
        client_alpha.wait_for_state_on_any_derp([telio.State.Connected]),
        client_beta.wait_for_state_on_any_derp([telio.State.Connected]),
        client_gamma.wait_for_state_on_any_derp([telio.State.Connected]),
    )
    # Note: GAMMA is symmetric, so it will not connect to ALPHA or BETA in direct mode
    await asyncio.gather(
        client_alpha.wait_for_state_peer(
            beta.public_key,
            [telio.State.Connected],
            [PathType.Direct],
        ),
        client_alpha.wait_for_state_peer(gamma.public_key, [telio.State.Connected]),
        client_beta.wait_for_state_peer(
            alpha.public_key,
            [telio.State.Connected],
            [PathType.Direct],
        ),
        client_beta.wait_for_state_peer(gamma.public_key, [telio.State.Connected]),
        client_gamma.wait_for_state_peer(alpha.public_key, [telio.State.Connected]),
        client_gamma.wait_for_state_peer(beta.public_key, [telio.State.Connected]),
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

    assert alpha_conn_tracker.get_out_of_limits() is None
    assert beta_conn_tracker.get_out_of_limits() is None
    assert gamma_conn_tracker.get_out_of_limits() is None

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


def add_rtt_validators(
    validator: EventValidator,
    ip_stacks: List[Optional[IPStack]],
):
    node_ip_stacks = dict(zip(NODES_FINGERPRINTS, ip_stacks))
    primary_node_ip_stack = node_ip_stacks.pop(validator.node_fingerprint)

    for fingerprint in node_ip_stacks:
        secondary_node_ip_stack = node_ip_stacks.get(fingerprint)
        if secondary_node_ip_stack is not None:
            validator.add_rtt_validator(
                exists=True,
                members=[fingerprint],
                does_not_contain=(
                    ["0:0:0:0:0"]
                    if primary_node_ip_stack is not IPStack.IPv6
                    and secondary_node_ip_stack is not IPStack.IPv6
                    else None
                ),
                contains=(
                    ["0:0:0:0:0"]
                    if primary_node_ip_stack is IPStack.IPv6
                    or secondary_node_ip_stack is IPStack.IPv6
                    else None
                ),
            ).add_rtt_loss_validator(
                exists=True,
                members=[fingerprint],
                contains=(
                    ["100:100:100:100:100"]
                    if primary_node_ip_stack is IPStack.IPv6
                    and secondary_node_ip_stack is not IPStack.IPv6
                    else ["0:0:0:0:0"]
                ),
            ).add_rtt6_validator(
                exists=True,
                members=[fingerprint],
                does_not_contain=(
                    ["0:0:0:0:0"]
                    if primary_node_ip_stack is not IPStack.IPv4
                    and secondary_node_ip_stack is not IPStack.IPv4
                    else None
                ),
                contains=(
                    ["0:0:0:0:0"]
                    if primary_node_ip_stack is IPStack.IPv4
                    or secondary_node_ip_stack is IPStack.IPv4
                    else None
                ),
            ).add_rtt6_loss_validator(
                exists=True,
                members=[fingerprint],
                contains=(
                    ["100:100:100:100:100"]
                    if primary_node_ip_stack is IPStack.IPv4
                    and secondary_node_ip_stack is not IPStack.IPv4
                    else ["0:0:0:0:0"]
                ),
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
            basic_validator(ALPHA_FINGERPRINT, meshnet_id=expected_meshnet_id)
            .add_external_links_validator(exists=False)
            .add_connectivity_matrix_validator(
                expected_states=alpha_expected_states,
                exists=True,
                no_of_connections=3,
                all_connections_up=False,
            )
            .add_members_validator(
                exists=True,
                contains=NODES_FINGERPRINTS,
            )
            .add_nat_type_validators(
                is_nat_type_collection_enabled=COLLECT_NAT_TYPE,
                nat_type="PortRestrictedCone",
                nat_mem=["Symmetric", "PortRestrictedCone"],
            )
            .add_sent_data_validator(
                exists=True,
                members=[BETA_FINGERPRINT, GAMMA_FINGERPRINT],
                does_not_contain=["0:0:0:0:0"],
            )
            .add_received_data_validator(
                exists=True,
                members=[BETA_FINGERPRINT, GAMMA_FINGERPRINT],
                does_not_contain=["0:0:0:0:0"],
            )
            .add_derp_conn_info_validator(
                exists=True,
                servers=DERP_SERVERS_STRS,
            )
            .add_nat_traversal_conn_info_peer_validator(
                alpha_pubkey,
                beta_pubkey,
                False,
                does_not_contain=["0:0:0:0:0:0"],
                count=1,
            )
        )
        add_rtt_validators(
            alpha_validator, [alpha_ip_stack, beta_ip_stack, gamma_ip_stack]
        )

        res = alpha_validator.validate(alpha_events[0])
        assert res[0], res[1]

        beta_validator = (
            basic_validator(BETA_FINGERPRINT, meshnet_id=expected_meshnet_id)
            .add_external_links_validator(exists=False)
            .add_connectivity_matrix_validator(
                exists=True,
                no_of_connections=3,
                all_connections_up=False,
                expected_states=beta_expected_states,
            )
            .add_members_validator(
                exists=True,
                contains=NODES_FINGERPRINTS,
            )
            .add_nat_type_validators(
                is_nat_type_collection_enabled=COLLECT_NAT_TYPE,
                nat_type="PortRestrictedCone",
                nat_mem=["PortRestrictedCone", "Symmetric"],
            )
            .add_sent_data_validator(
                exists=True,
                members=[ALPHA_FINGERPRINT, GAMMA_FINGERPRINT],
                does_not_contain=["0:0:0:0:0"],
            )
            .add_received_data_validator(
                exists=True,
                members=[ALPHA_FINGERPRINT, GAMMA_FINGERPRINT],
                does_not_contain=["0:0:0:0:0"],
            )
            .add_derp_conn_info_validator(
                exists=True,
                servers=DERP_SERVERS_STRS,
            )
            .add_nat_traversal_conn_info_peer_validator(
                beta_pubkey,
                alpha_pubkey,
                False,
                does_not_contain=["0:0:0:0:0:0"],
                count=1,
            )
        )
        add_rtt_validators(
            beta_validator, [alpha_ip_stack, beta_ip_stack, gamma_ip_stack]
        )

        res = beta_validator.validate(beta_events[0])
        assert res[0], res[1]

        gamma_validator = (
            basic_validator(GAMMA_FINGERPRINT, meshnet_id=expected_meshnet_id)
            .add_external_links_validator(exists=False)
            .add_connectivity_matrix_validator(
                exists=True,
                no_of_connections=3,
                all_connections_up=False,
                expected_states=gamma_expected_states,
            )
            .add_members_validator(
                exists=True,
                contains=NODES_FINGERPRINTS,
            )
            .add_nat_type_validators(
                is_nat_type_collection_enabled=COLLECT_NAT_TYPE,
                nat_type="Symmetric",
                nat_mem=["PortRestrictedCone", "PortRestrictedCone"],
            )
            .add_sent_data_validator(
                exists=True,
                members=[ALPHA_FINGERPRINT, BETA_FINGERPRINT],
                does_not_contain=["0:0:0:0:0"],
            )
            .add_received_data_validator(
                exists=True,
                members=[ALPHA_FINGERPRINT, BETA_FINGERPRINT],
                does_not_contain=["0:0:0:0:0"],
            )
            .add_derp_conn_info_validator(
                exists=True,
                servers=DERP_SERVERS_STRS,
            )
            .add_nat_traversal_conn_info_peer_validator(
                gamma_pubkey,
                "",
                True,
            )
        )
        add_rtt_validators(
            gamma_validator, [alpha_ip_stack, beta_ip_stack, gamma_ip_stack]
        )
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
            basic_validator(ALPHA_FINGERPRINT)
            .add_external_links_validator(
                exists=True,
                contains=[GAMMA_FINGERPRINT],
                does_not_contain=["vpn", alpha_events[0].fp, ALPHA_FINGERPRINT],
                all_connections_up=False,
                no_of_connections=1,
                expected_states=alpha_expected_states,
            )
            .add_connectivity_matrix_validator(
                exists=True,
                no_of_connections=1,
                all_connections_up=False,
                expected_states=alpha_expected_states,
            )
            .add_members_validator(
                exists=True,
                contains=[ALPHA_FINGERPRINT, BETA_FINGERPRINT],
                does_not_contain=[GAMMA_FINGERPRINT],
            )
            .add_nat_type_validators(
                is_nat_type_collection_enabled=COLLECT_NAT_TYPE,
                nat_type="PortRestrictedCone",
                nat_mem=["PortRestrictedCone", "Symmetric"],
            )
            .add_sent_data_validator(
                exists=True,
                members=[BETA_FINGERPRINT, GAMMA_FINGERPRINT],
                does_not_contain=["0:0:0:0:0"],
            )
            .add_received_data_validator(
                exists=True,
                members=[BETA_FINGERPRINT, GAMMA_FINGERPRINT],
                does_not_contain=["0:0:0:0:0"],
            )
            .add_derp_conn_info_validator(
                exists=True,
                servers=DERP_SERVERS_STRS,
            )
            .add_nat_traversal_conn_info_peer_validator(
                alpha_pubkey,
                beta_pubkey,
                False,
                does_not_contain=["0:0:0:0:0:0"],
                count=1,
            )
        )
        add_rtt_validators(
            alpha_validator, [alpha_ip_stack, beta_ip_stack, gamma_ip_stack]
        )

        res = alpha_validator.validate(alpha_events[0])
        assert res[0], res[1]

        beta_validator = (
            basic_validator(BETA_FINGERPRINT)
            .add_external_links_validator(
                exists=True,
                contains=[GAMMA_FINGERPRINT],
                does_not_contain=["vpn", beta_events[0].fp, BETA_FINGERPRINT],
                all_connections_up=False,
                no_of_connections=1,
                expected_states=beta_expected_states,
            )
            .add_connectivity_matrix_validator(
                exists=True,
                no_of_connections=1,
                all_connections_up=False,
                expected_states=beta_expected_states,
            )
            .add_members_validator(
                exists=True,
                contains=[ALPHA_FINGERPRINT, BETA_FINGERPRINT],
                does_not_contain=[GAMMA_FINGERPRINT],
            )
            .add_nat_type_validators(
                is_nat_type_collection_enabled=COLLECT_NAT_TYPE,
                nat_type="PortRestrictedCone",
                nat_mem=["PortRestrictedCone", "Symmetric"],
            )
            .add_sent_data_validator(
                exists=True,
                members=[ALPHA_FINGERPRINT, GAMMA_FINGERPRINT],
                does_not_contain=["0:0:0:0:0"],
            )
            .add_received_data_validator(
                exists=True,
                members=[ALPHA_FINGERPRINT, GAMMA_FINGERPRINT],
                does_not_contain=["0:0:0:0:0"],
            )
            .add_derp_conn_info_validator(
                exists=True,
                servers=DERP_SERVERS_STRS,
            )
            .add_nat_traversal_conn_info_peer_validator(
                beta_pubkey,
                alpha_pubkey,
                False,
                does_not_contain=["0:0:0:0:0:0"],
                count=1,
            )
        )
        add_rtt_validators(
            beta_validator, [alpha_ip_stack, beta_ip_stack, gamma_ip_stack]
        )

        res = beta_validator.validate(beta_events[0])
        assert res[0], res[1]

        gamma_validator = (
            basic_validator(GAMMA_FINGERPRINT)
            .add_external_links_validator(
                exists=True,
                contains=[ALPHA_FINGERPRINT, BETA_FINGERPRINT],
                does_not_contain=["vpn", gamma_events[0].fp, GAMMA_FINGERPRINT],
                all_connections_up=False,
                no_of_connections=2,
                expected_states=gamma_expected_states,
            )
            .add_connectivity_matrix_validator(exists=False)
            .add_nat_type_validators(
                is_nat_type_collection_enabled=COLLECT_NAT_TYPE,
                nat_type="Symmetric",
                nat_mem=["PortRestrictedCone", "PortRestrictedCone"],
            )
            .add_sent_data_validator(
                exists=True,
                members=[ALPHA_FINGERPRINT, BETA_FINGERPRINT],
                does_not_contain=["0:0:0:0:0"],
            )
            .add_received_data_validator(
                exists=True,
                members=[ALPHA_FINGERPRINT, BETA_FINGERPRINT],
                does_not_contain=["0:0:0:0:0"],
            )
            .add_derp_conn_info_validator(
                exists=True,
                servers=DERP_SERVERS_STRS,
            )
            .add_nat_traversal_conn_info_peer_validator(
                gamma_pubkey,
                "",
                True,
            )
        )
        add_rtt_validators(
            gamma_validator, [alpha_ip_stack, beta_ip_stack, gamma_ip_stack]
        )
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
            basic_validator(ALPHA_FINGERPRINT)
            .add_external_links_validator(
                exists=True,
                contains=[BETA_FINGERPRINT, GAMMA_FINGERPRINT],
                does_not_contain=["vpn", alpha_events[0].fp, ALPHA_FINGERPRINT],
                all_connections_up=False,
                no_of_connections=2,
                expected_states=alpha_expected_states,
            )
            .add_connectivity_matrix_validator(exists=False)
            .add_nat_type_validators(
                is_nat_type_collection_enabled=COLLECT_NAT_TYPE,
                nat_type="PortRestrictedCone",
                nat_mem=["Symmetric", "PortRestrictedCone"],
            )
            .add_sent_data_validator(
                exists=True,
                members=[BETA_FINGERPRINT, GAMMA_FINGERPRINT],
                does_not_contain=["0:0:0:0:0"],
            )
            .add_received_data_validator(
                exists=True,
                members=[BETA_FINGERPRINT, GAMMA_FINGERPRINT],
                does_not_contain=["0:0:0:0:0"],
            )
            .add_derp_conn_info_validator(
                exists=True,
                servers=DERP_SERVERS_STRS,
            )
            .add_nat_traversal_conn_info_peer_validator(
                alpha_pubkey,
                beta_pubkey,
                False,
                does_not_contain=["0:0:0:0:0:0"],
                count=1,
            )
        )
        add_rtt_validators(
            alpha_validator, [alpha_ip_stack, beta_ip_stack, gamma_ip_stack]
        )

        res = alpha_validator.validate(alpha_events[0])
        assert res[0], res[1]

        beta_validator = (
            basic_validator(BETA_FINGERPRINT)
            .add_external_links_validator(
                exists=True,
                contains=[ALPHA_FINGERPRINT, GAMMA_FINGERPRINT],
                does_not_contain=["vpn", beta_events[0].fp, BETA_FINGERPRINT],
                all_connections_up=False,
                no_of_connections=2,
                expected_states=beta_expected_states,
            )
            .add_connectivity_matrix_validator(exists=False)
            .add_nat_type_validators(
                is_nat_type_collection_enabled=COLLECT_NAT_TYPE,
                nat_type="PortRestrictedCone",
                nat_mem=["PortRestrictedCone", "Symmetric"],
            )
            .add_sent_data_validator(
                exists=True,
                members=[ALPHA_FINGERPRINT, GAMMA_FINGERPRINT],
                does_not_contain=["0:0:0:0:0"],
            )
            .add_received_data_validator(
                exists=True,
                members=[ALPHA_FINGERPRINT, GAMMA_FINGERPRINT],
                does_not_contain=["0:0:0:0:0"],
            )
            .add_derp_conn_info_validator(
                exists=True,
                servers=DERP_SERVERS_STRS,
            )
            .add_nat_traversal_conn_info_peer_validator(
                beta_pubkey,
                alpha_pubkey,
                False,
                does_not_contain=["0:0:0:0:0:0"],
                count=1,
            )
        )
        add_rtt_validators(
            beta_validator, [alpha_ip_stack, beta_ip_stack, gamma_ip_stack]
        )

        res = beta_validator.validate(beta_events[0])
        assert res[0], res[1]

        gamma_validator = (
            basic_validator(GAMMA_FINGERPRINT)
            .add_external_links_validator(
                exists=True,
                contains=[ALPHA_FINGERPRINT, BETA_FINGERPRINT],
                does_not_contain=["vpn", gamma_events[0].fp, GAMMA_FINGERPRINT],
                all_connections_up=False,
                no_of_connections=2,
                expected_states=gamma_expected_states,
            )
            .add_connectivity_matrix_validator(exists=False)
            .add_nat_type_validators(
                is_nat_type_collection_enabled=COLLECT_NAT_TYPE,
                nat_type="Symmetric",
                nat_mem=["PortRestrictedCone", "PortRestrictedCone"],
            )
            .add_sent_data_validator(
                exists=True,
                members=[ALPHA_FINGERPRINT, BETA_FINGERPRINT],
                does_not_contain=["0:0:0:0:0"],
            )
            .add_received_data_validator(
                exists=True,
                members=[ALPHA_FINGERPRINT, BETA_FINGERPRINT],
                does_not_contain=["0:0:0:0:0"],
            )
            .add_derp_conn_info_validator(
                exists=True,
                servers=DERP_SERVERS_STRS,
            )
            .add_nat_traversal_conn_info_peer_validator(
                gamma_pubkey,
                "",
                True,
            )
        )
        add_rtt_validators(
            gamma_validator, [alpha_ip_stack, beta_ip_stack, gamma_ip_stack]
        )
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
            basic_validator(ALPHA_FINGERPRINT, meshnet_id=expected_meshnet_id)
            .add_external_links_validator(
                exists=True,
                contains=["vpn"],
                all_connections_up=False,
                no_of_connections=1,
                no_of_vpn=1,
                expected_states=alpha_expected_states,
            )
            .add_connectivity_matrix_validator(
                exists=True,
                no_of_connections=3,
                all_connections_up=False,
                expected_states=alpha_expected_states,
            )
            .add_members_validator(
                exists=True,
                contains=NODES_FINGERPRINTS,
            )
            .add_nat_type_validators(
                is_nat_type_collection_enabled=COLLECT_NAT_TYPE,
                nat_type="Symmetric",
                nat_mem=["Symmetric", "PortRestrictedCone"],
            )
            .add_rtt_validator(
                exists=True,
                members=["vpn"],
                contains=["0:0:0:0:0"] if alpha_ip_stack is IPStack.IPv6 else None,
                does_not_contain=(
                    ["0:0:0:0:0"] if alpha_ip_stack is not IPStack.IPv6 else None
                ),
            )
            .add_rtt_loss_validator(
                exists=True,
                members=["vpn"],
                contains=(
                    ["100:100:100:100:100"]
                    if alpha_ip_stack is IPStack.IPv6
                    else ["0:0:0:0:0"]
                ),
            )
            .add_rtt6_validator(
                exists=True,
                members=["vpn"],
                # TODO: At the moment VPN IPv6 Address is not reachable
                contains=["0:0:0:0:0"],
            )
            .add_rtt6_loss_validator(
                exists=True,
                members=["vpn"],
                # TODO: At the moment VPN IPv6 Address is not reachable
                contains=(
                    ["0:0:0:0:0"]
                    if alpha_ip_stack is IPStack.IPv4
                    else ["100:100:100:100:100"]
                ),
            )
            .add_sent_data_validator(
                exists=True,
                members=[BETA_FINGERPRINT, GAMMA_FINGERPRINT, "vpn"],
                does_not_contain=["0:0:0:0:0"],
            )
            .add_received_data_validator(
                exists=True,
                members=[BETA_FINGERPRINT, GAMMA_FINGERPRINT, "vpn"],
                does_not_contain=["0:0:0:0:0"],
            )
            .add_derp_conn_info_validator(
                exists=True,
                servers=DERP_SERVERS_STRS,
            )
            .add_nat_traversal_conn_info_peer_validator(
                alpha_pubkey,
                beta_pubkey,
                False,
                does_not_contain=["0:0:0:0:0:0"],
                count=1,
            )
        )
        add_rtt_validators(
            alpha_validator, [alpha_ip_stack, beta_ip_stack, gamma_ip_stack]
        )

        res = alpha_validator.validate(alpha_events[0])
        assert res[0], res[1]

        beta_validator = (
            basic_validator(BETA_FINGERPRINT, meshnet_id=expected_meshnet_id)
            .add_external_links_validator(exists=False)
            .add_connectivity_matrix_validator(
                exists=True,
                no_of_connections=3,
                all_connections_up=False,
                expected_states=beta_expected_states,
            )
            .add_members_validator(
                exists=True,
                contains=NODES_FINGERPRINTS,
            )
            .add_nat_type_validators(
                is_nat_type_collection_enabled=COLLECT_NAT_TYPE,
                nat_type="PortRestrictedCone",
                nat_mem=["Symmetric", "Symmetric"],
            )
            .add_sent_data_validator(
                exists=True,
                members=[ALPHA_FINGERPRINT, GAMMA_FINGERPRINT],
                does_not_contain=["0:0:0:0:0"],
            )
            .add_received_data_validator(
                exists=True,
                members=[ALPHA_FINGERPRINT, GAMMA_FINGERPRINT],
                does_not_contain=["0:0:0:0:0"],
            )
            .add_derp_conn_info_validator(
                exists=True,
                servers=DERP_SERVERS_STRS,
            )
            .add_nat_traversal_conn_info_peer_validator(
                beta_pubkey,
                alpha_pubkey,
                False,
                does_not_contain=["0:0:0:0:0:0"],
                count=1,
            )
        )
        add_rtt_validators(
            beta_validator, [alpha_ip_stack, beta_ip_stack, gamma_ip_stack]
        )

        res = beta_validator.validate(beta_events[0])
        assert res[0], res[1]

        gamma_validator = (
            basic_validator(GAMMA_FINGERPRINT, meshnet_id=expected_meshnet_id)
            .add_external_links_validator(exists=False)
            .add_connectivity_matrix_validator(
                exists=True,
                no_of_connections=3,
                all_connections_up=False,
                expected_states=gamma_expected_states,
            )
            .add_members_validator(
                exists=True,
                contains=NODES_FINGERPRINTS,
            )
            .add_nat_type_validators(
                is_nat_type_collection_enabled=COLLECT_NAT_TYPE,
                nat_type="Symmetric",
                nat_mem=["Symmetric", "PortRestrictedCone"],
            )
            .add_sent_data_validator(
                exists=True,
                members=[ALPHA_FINGERPRINT, BETA_FINGERPRINT],
                does_not_contain=["0:0:0:0:0"],
            )
            .add_received_data_validator(
                exists=True,
                members=[ALPHA_FINGERPRINT, BETA_FINGERPRINT],
                does_not_contain=["0:0:0:0:0"],
            )
            .add_derp_conn_info_validator(
                exists=True,
                servers=DERP_SERVERS_STRS,
            )
            .add_nat_traversal_conn_info_peer_validator(
                gamma_pubkey,
                "",
                True,
            )
        )
        add_rtt_validators(
            gamma_validator, [alpha_ip_stack, beta_ip_stack, gamma_ip_stack]
        )
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

        client_alpha = await exit_stack.enter_async_context(
            telio.Client(
                connection_alpha,
                alpha,
                telio_features=build_telio_features(ALPHA_FINGERPRINT),
            ).run(api.get_meshmap(alpha.id))
        )
        client_beta = await exit_stack.enter_async_context(
            telio.Client(
                connection_beta,
                beta,
                telio_features=build_telio_features(BETA_FINGERPRINT),
            ).run(api.get_meshmap(beta.id))
        )

        await asyncio.gather(
            client_alpha.wait_for_state_on_any_derp([telio.State.Connected]),
            client_beta.wait_for_state_on_any_derp([telio.State.Connected]),
        )
        await asyncio.gather(
            client_alpha.wait_for_state_peer(beta.public_key, [telio.State.Connected]),
            client_beta.wait_for_state_peer(alpha.public_key, [telio.State.Connected]),
        )

        async with Ping(
            connection_alpha,
            testing.unpack_optional(
                beta.get_ip_address(IPProto.IPv6 if is_stun6_needed else IPProto.IPv4)
            ),
        ).run() as ping:
            await ping.wait_for_next_ping()

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
            basic_validator(ALPHA_FINGERPRINT)
            .add_external_links_validator(exists=False)
            .add_connectivity_matrix_validator(
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
            )
            .add_members_validator(
                exists=True, contains=[ALPHA_FINGERPRINT, BETA_FINGERPRINT]
            )
            .add_nat_type_validators(
                is_nat_type_collection_enabled=COLLECT_NAT_TYPE,
                nat_type="PortRestrictedCone",
                nat_mem=[],
            )
            .add_sent_data_validator(
                exists=True,
                members=[BETA_FINGERPRINT],
                does_not_contain=["0:0:0:0:0"],
            )
            .add_received_data_validator(
                exists=True,
                members=[BETA_FINGERPRINT],
                does_not_contain=["0:0:0:0:0"],
            )
            .add_derp_conn_info_validator(
                exists=True,
                servers=DERP_SERVERS_STRS,
            )
            .add_nat_traversal_conn_info_peer_validator(
                alpha.public_key,
                beta.public_key,
                False,
                does_not_contain=["0:0:0:0:0:0"],
                count=1,
            )
        )
        add_rtt_validators(alpha_validator, [alpha_ip_stack, beta_ip_stack, None])

        res = alpha_validator.validate(alpha_events[0])
        assert res[0], res[1]

        beta_validator = (
            basic_validator(BETA_FINGERPRINT)
            .add_external_links_validator(exists=False)
            .add_connectivity_matrix_validator(
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
            )
            .add_members_validator(
                exists=True, contains=[ALPHA_FINGERPRINT, BETA_FINGERPRINT]
            )
            .add_nat_type_validators(
                is_nat_type_collection_enabled=COLLECT_NAT_TYPE,
                nat_type="PortRestrictedCone",
                nat_mem=[],
            )
            .add_sent_data_validator(
                exists=True,
                members=[ALPHA_FINGERPRINT],
                does_not_contain=["0:0:0:0:0"],
            )
            .add_received_data_validator(
                exists=True,
                members=[ALPHA_FINGERPRINT],
                does_not_contain=["0:0:0:0:0"],
            )
            .add_derp_conn_info_validator(
                exists=True,
                servers=DERP_SERVERS_STRS,
            )
            .add_nat_traversal_conn_info_peer_validator(
                beta.public_key,
                alpha.public_key,
                False,
                does_not_contain=["0:0:0:0:0:0"],
                count=1,
            )
        )
        add_rtt_validators(beta_validator, [alpha_ip_stack, beta_ip_stack, None])

        res = beta_validator.validate(beta_events[0])
        assert res[0], res[1]

        # Validate all nodes have the same meshnet id
        assert alpha_events[0].fp == beta_events[0].fp

        assert alpha_conn_tracker.get_out_of_limits() is None
        assert beta_conn_tracker.get_out_of_limits() is None


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
        def get_features_with_long_qos(fingerprint: str) -> TelioFeatures:
            features = build_telio_features(fingerprint)
            assert features.nurse is not None
            assert features.nurse.qos is not None
            features.nurse.qos.rtt_interval = RTT_INTERVAL * 10
            return features

        client_alpha = await exit_stack.enter_async_context(
            telio.Client(
                connection_alpha,
                alpha,
                telio_features=get_features_with_long_qos(ALPHA_FINGERPRINT),
            ).run(api.get_meshmap(alpha.id))
        )
        client_beta = await exit_stack.enter_async_context(
            telio.Client(
                connection_beta,
                beta,
                telio_features=get_features_with_long_qos(BETA_FINGERPRINT),
            ).run(api.get_meshmap(beta.id))
        )

        await asyncio.gather(
            client_alpha.wait_for_state_on_any_derp([telio.State.Connected]),
            client_beta.wait_for_state_on_any_derp([telio.State.Connected]),
        )
        await asyncio.gather(
            client_alpha.wait_for_state_peer(beta.public_key, [telio.State.Connected]),
            client_beta.wait_for_state_peer(alpha.public_key, [telio.State.Connected]),
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
        # disconnect beta and trigger analytics on alpha
        await client_beta.stop_device()

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
            basic_validator(ALPHA_FINGERPRINT)
            .add_external_links_validator(exists=False)
            .add_connectivity_matrix_validator(
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
            )
            .add_members_validator(
                exists=True, contains=[ALPHA_FINGERPRINT, BETA_FINGERPRINT]
            )
            .add_nat_type_validators(
                is_nat_type_collection_enabled=COLLECT_NAT_TYPE,
                nat_type="PortRestrictedCone",
                nat_mem=[],
            )
            .add_sent_data_validator(
                exists=True,
                members=[BETA_FINGERPRINT],
                does_not_contain=["0:0:0:0:0"],
            )
            .add_received_data_validator(
                exists=True,
                members=[BETA_FINGERPRINT],
                does_not_contain=["0:0:0:0:0"],
            )
            .add_derp_conn_info_validator(
                exists=True,
                servers=DERP_SERVERS_STRS,
            )
            .add_nat_traversal_conn_info_peer_validator(
                alpha.public_key,
                beta.public_key,
                False,
                does_not_contain=["0:0:0:0:0:0"],
                count=1,
            )
        )
        add_rtt_validators(alpha_validator, [alpha_ip_stack, beta_ip_stack, None])

        beta_validator = (
            basic_validator(BETA_FINGERPRINT)
            .add_external_links_validator(exists=False)
            .add_connectivity_matrix_validator(
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
            )
            .add_members_validator(
                exists=True, contains=[ALPHA_FINGERPRINT, BETA_FINGERPRINT]
            )
            .add_nat_type_validators(
                is_nat_type_collection_enabled=COLLECT_NAT_TYPE,
                nat_type="PortRestrictedCone",
                nat_mem=[],
            )
            .add_sent_data_validator(
                exists=True,
                members=[ALPHA_FINGERPRINT],
                does_not_contain=["0:0:0:0:0"],
            )
            .add_received_data_validator(
                exists=True,
                members=[ALPHA_FINGERPRINT],
                does_not_contain=["0:0:0:0:0"],
            )
            .add_derp_conn_info_validator(
                exists=True,
                servers=DERP_SERVERS_STRS,
            )
            .add_nat_traversal_conn_info_peer_validator(
                beta.public_key,
                alpha.public_key,
                False,
                does_not_contain=["0:0:0:0:0:0"],
                count=1,
            )
        )
        add_rtt_validators(beta_validator, [alpha_ip_stack, beta_ip_stack, None])

        res = alpha_validator.validate(alpha_events[0])
        assert res[0], res[1]
        res = beta_validator.validate(beta_events[0])
        assert res[0], res[1]

        # Connectivity matrix is not persistent, will be missing when peer is offline
        alpha_validator = (
            basic_validator(ALPHA_FINGERPRINT)
            .add_external_links_validator(exists=False)
            .add_connectivity_matrix_validator(exists=False)
            .add_members_validator(
                exists=True, contains=[ALPHA_FINGERPRINT, BETA_FINGERPRINT]
            )
            .add_nat_type_validators(
                is_nat_type_collection_enabled=COLLECT_NAT_TYPE,
                nat_type="PortRestrictedCone",
                nat_mem=[],
            )
            .add_rtt_validator(
                exists=True,
                members=[BETA_FINGERPRINT],
                contains=["0:0:0:0:0"],
            )
            .add_rtt_loss_validator(
                exists=True,
                members=[BETA_FINGERPRINT],
                contains=(
                    ["100:100:100:100:100"]
                    if beta_ip_stack is not IPStack.IPv6
                    else ["0:0:0:0:0"]
                ),
            )
            .add_rtt6_validator(
                exists=True,
                members=[BETA_FINGERPRINT],
                contains=["0:0:0:0:0"],
            )
            .add_rtt6_loss_validator(
                exists=True,
                members=[BETA_FINGERPRINT],
                contains=(
                    ["100:100:100:100:100"]
                    if beta_ip_stack is not IPStack.IPv4
                    else ["0:0:0:0:0"]
                ),
            )
            .add_sent_data_validator(
                exists=True,
                members=[BETA_FINGERPRINT],
                does_not_contain=["0:0:0:0:0"],
            )
            .add_received_data_validator(
                exists=True,
                members=[BETA_FINGERPRINT],
            )
            .add_derp_conn_info_validator(
                exists=False,
            )
            .add_derp_conn_info_validator(
                exists=False,
            )
            .add_nat_traversal_conn_info_peer_validator(
                alpha.public_key,
                beta.public_key,
                False,
                does_not_contain=["0:0:0:0:0:0"],
                count=1,
            )
        )

        res = alpha_validator.validate(alpha_events[1])
        assert res[0], res[1]

        beta_validator = (
            EventValidator(BETA_FINGERPRINT)
            .add_name_validator("disconnect")
            .add_category_validator("service_quality")
            .add_fingerprint_validator(exists=True)
            .add_external_links_validator(exists=False)
            .add_connectivity_matrix_validator(
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
            )
            .add_members_validator(
                exists=True, contains=[ALPHA_FINGERPRINT, BETA_FINGERPRINT]
            )
            .add_rtt_validator(
                exists=False,
            )
            .add_rtt_loss_validator(
                exists=False,
            )
            .add_rtt6_validator(
                exists=False,
            )
            .add_rtt6_loss_validator(
                exists=False,
            )
            .add_sent_data_validator(
                exists=False,
            )
            .add_received_data_validator(
                exists=False,
            )
            .add_derp_conn_info_validator(
                exists=True,
                servers=DERP_SERVERS_STRS,
            )
            .add_nat_traversal_conn_info_peer_validator(
                beta.public_key,
                alpha.public_key,
                False,
                does_not_contain=["0:0:0:0:0:0"],
                count=1,
            )
        )

        res = beta_validator.validate(beta_events[1])
        assert res[0], res[1]

        # Validate all nodes have the same meshnet id
        assert (
            alpha_events[0].fp
            == alpha_events[1].fp
            == beta_events[0].fp
            == beta_events[1].fp
        )
        assert alpha_conn_tracker.get_out_of_limits() is None
        assert beta_conn_tracker.get_out_of_limits() is None


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
                telio_features=build_telio_features(BETA_FINGERPRINT),
            ).run(api.get_meshmap(beta.id))
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
                telio_features=build_telio_features(ALPHA_FINGERPRINT),
            ).run(api.get_meshmap(alpha.id))
        )

        beta.set_peer_firewall_settings(alpha.id, allow_incoming_connections=True)
        await client_beta.set_meshmap(api.get_meshmap(beta.id))

        await asyncio.gather(
            client_alpha.wait_for_state_peer(beta.public_key, [telio.State.Connected]),
            client_beta.wait_for_state_peer(alpha.public_key, [telio.State.Connected]),
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

        assert alpha_conn_tracker.get_out_of_limits() is None
        assert beta_conn_tracker.get_out_of_limits() is None


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

        client_beta = await exit_stack.enter_async_context(
            telio.Client(
                connection_beta,
                beta,
                telio_features=build_telio_features(BETA_FINGERPRINT),
            ).run(api.get_meshmap(beta.id))
        )

        await client_beta.trigger_event_collection()
        beta_events = await wait_for_event_dump(
            ConnectionTag.DOCKER_CONE_CLIENT_2, BETA_EVENTS_PATH, nr_events=1
        )
        assert beta_events
        initial_beta_meshnet_id = beta_events[0].fp

        await client_beta.quit()
        api.remove(beta.id)

        beta = api.default_config_one_node(True, ip_stack=alpha_ip_stack)
        connection_beta = await exit_stack.enter_async_context(
            new_connection_by_tag(ConnectionTag.DOCKER_CONE_CLIENT_2)
        )

        client_beta = await exit_stack.enter_async_context(
            telio.Client(
                connection_beta,
                beta,
                telio_features=build_telio_features(BETA_FINGERPRINT),
            ).run(api.get_meshmap(beta.id))
        )

        await client_beta.trigger_event_collection()
        beta_events = await wait_for_event_dump(
            ConnectionTag.DOCKER_CONE_CLIENT_2, BETA_EVENTS_PATH, nr_events=2
        )
        assert beta_events
        second_beta_meshnet_id = beta_events[0].fp

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
                    ALPHA_FINGERPRINT,
                    initial_heartbeat_interval=initial_heartbeat_interval,
                ),
            ).run(api.get_meshmap(alpha.id))
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
