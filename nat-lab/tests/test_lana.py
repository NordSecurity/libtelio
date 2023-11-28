# pylint: disable=too-many-lines

import asyncio
import base64
import pytest
import subprocess
import telio
from config import WG_SERVER
from contextlib import AsyncExitStack
from mesh_api import API, Node
from telio_features import TelioFeatures, Nurse, Lana, Qos
from typing import Optional
from utils import testing
from utils.analytics import (
    fetch_moose_events,
    basic_validator,
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
)
from utils.ping import Ping
from utils.router import IPStack, IPProto

CONTAINER_EVENT_PATH = "/event.db"
ALPHA_EVENTS_PATH = "./alpha-events.db"
BETA_EVENTS_PATH = "./beta-events.db"
GAMMA_EVENTS_PATH = "./gamma-events.db"

DEFAULT_WAITING_TIME = 3
DEFAULT_CHECK_INTERVAL = 2
DEFAULT_CHECK_TIMEOUT = 60
COLLECT_NAT_TYPE = False

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
    fingerprint: str, initial_heartbeat_interval: Optional[int] = None
) -> TelioFeatures:
    return TelioFeatures(
        lana=Lana(prod=False, event_path=CONTAINER_EVENT_PATH),
        nurse=Nurse(
            fingerprint=fingerprint,
            heartbeat_interval=3600,
            initial_heartbeat_interval=initial_heartbeat_interval,
            qos=Qos(rtt_interval=10, buckets=5),
            enable_nat_type_collection=COLLECT_NAT_TYPE,
        ),
    )


async def clean_container(connection):
    await testing.wait_long(
        connection.create_process(["rm", "-f", CONTAINER_EVENT_PATH]).execute()
    )
    await testing.wait_long(
        connection.create_process(
            ["rm", "-f", CONTAINER_EVENT_PATH + "-journal"]
        ).execute()
    )


def get_moose_db_file(container_tag, container_path, local_path):
    subprocess.run(["rm", "-f", local_path])
    subprocess.run(
        ["docker", "cp", container_id(container_tag) + ":" + container_path, local_path]
    )


async def wait_for_event_dump(container, events_path, nr_events):
    start_time = asyncio.get_event_loop().time()

    while asyncio.get_event_loop().time() - start_time < DEFAULT_CHECK_TIMEOUT:
        get_moose_db_file(container, CONTAINER_EVENT_PATH, events_path)
        events = fetch_moose_events(events_path)
        if len(events) == nr_events:
            return events
        await asyncio.sleep(DEFAULT_CHECK_INTERVAL)
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
        await testing.wait_long(ping.wait_for_next_ping())


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

    # Cleanup
    await clean_container(connection_alpha)
    await clean_container(connection_beta)
    await clean_container(connection_gamma)

    client_alpha = await exit_stack.enter_async_context(
        telio.Client(
            connection_alpha,
            alpha,
            telio_features=build_telio_features("alpha_fingerprint"),
        ).run(api.get_meshmap(alpha.id))
    )

    client_beta = await exit_stack.enter_async_context(
        telio.Client(
            connection_beta,
            beta,
            telio_features=build_telio_features("beta_fingerprint"),
        ).run(api.get_meshmap(beta.id))
    )

    client_gamma = await exit_stack.enter_async_context(
        telio.Client(
            connection_gamma,
            gamma,
            telio_features=build_telio_features("gamma_fingerprint"),
        ).run(api.get_meshmap(gamma.id))
    )

    await asyncio.gather(
        client_alpha.wait_for_state_on_any_derp([telio.State.Connected]),
        client_beta.wait_for_state_on_any_derp([telio.State.Connected]),
        client_gamma.wait_for_state_on_any_derp([telio.State.Connected]),
    )
    await asyncio.gather(
        client_alpha.wait_for_state_peer(beta.public_key, [telio.State.Connected]),
        client_alpha.wait_for_state_peer(gamma.public_key, [telio.State.Connected]),
        client_beta.wait_for_state_peer(alpha.public_key, [telio.State.Connected]),
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

    await client_alpha.trigger_event_collection()
    await client_beta.trigger_event_collection()
    await client_gamma.trigger_event_collection()

    alpha_events = await wait_for_event_dump(
        ConnectionTag.DOCKER_CONE_CLIENT_1, ALPHA_EVENTS_PATH, nr_events=1
    )
    beta_events = await wait_for_event_dump(
        ConnectionTag.DOCKER_CONE_CLIENT_2, BETA_EVENTS_PATH, nr_events=1
    )
    gamma_events = await wait_for_event_dump(
        ConnectionTag.DOCKER_SYMMETRIC_CLIENT_1, GAMMA_EVENTS_PATH, nr_events=1
    )

    await asyncio.gather(
        client_alpha.stop_device(),
        client_beta.stop_device(),
        client_gamma.stop_device(),
    )

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
    ]


@pytest.mark.moose
@pytest.mark.asyncio
@pytest.mark.xfail(reason="test flaky - JIRA issue: LLT-4591")
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
        ] = await run_default_scenario(
            exit_stack=exit_stack,
            alpha_is_local=True,
            beta_is_local=True,
            gamma_is_local=True,
            alpha_ip_stack=alpha_ip_stack,
            beta_ip_stack=beta_ip_stack,
            gamma_ip_stack=gamma_ip_stack,
        )

        assert alpha_events
        assert beta_events
        assert gamma_events

        # Alpha has smallest public key when sorted lexicographically
        expected_meshnet_id = alpha_events[0].fp

        alpha_validator = (
            basic_validator(meshnet_id=expected_meshnet_id)
            .add_external_links_validator(exists=False)
            .add_connectivity_matrix_validator(
                expected_states=alpha_expected_states,
                exists=True,
                no_of_connections=3,
                all_connections_up=False,
            )
            .add_members_validator(
                exists=True,
                contains=["alpha_fingerprint", "beta_fingerprint", "gamma_fingerprint"],
            )
            .add_nat_type_validators(
                is_nat_type_collection_enabled=COLLECT_NAT_TYPE,
                nat_type="PortRestrictedCone",
                nat_mem=["Symmetric", "PortRestrictedCone"],
            )
        )

        assert alpha_validator.validate(alpha_events[0])

        beta_validator = (
            basic_validator(meshnet_id=expected_meshnet_id)
            .add_external_links_validator(exists=False)
            .add_connectivity_matrix_validator(
                exists=True,
                no_of_connections=3,
                all_connections_up=False,
                expected_states=beta_expected_states,
            )
            .add_members_validator(
                exists=True,
                contains=["alpha_fingerprint", "beta_fingerprint", "gamma_fingerprint"],
            )
            .add_nat_type_validators(
                is_nat_type_collection_enabled=COLLECT_NAT_TYPE,
                nat_type="PortRestrictedCone",
                nat_mem=["PortRestrictedCone", "Symmetric"],
            )
        )

        assert beta_validator.validate(beta_events[0])

        gamma_validator = (
            basic_validator(meshnet_id=expected_meshnet_id)
            .add_external_links_validator(exists=False)
            .add_connectivity_matrix_validator(
                exists=True,
                no_of_connections=3,
                all_connections_up=False,
                expected_states=gamma_expected_states,
            )
            .add_members_validator(
                exists=True,
                contains=["alpha_fingerprint", "beta_fingerprint", "gamma_fingerprint"],
            )
            .add_nat_type_validators(
                is_nat_type_collection_enabled=COLLECT_NAT_TYPE,
                nat_type="Symmetric",
                nat_mem=["PortRestrictedCone", "PortRestrictedCone"],
            )
        )

        assert gamma_validator.validate(gamma_events[0])


@pytest.mark.moose
@pytest.mark.asyncio
@pytest.mark.parametrize("alpha_ip_stack,beta_ip_stack", IP_STACK_TEST_CONFIGS)
async def test_lana_with_external_node(
    alpha_ip_stack: IPStack, beta_ip_stack: IPStack
) -> None:
    gamma_ip_stack = IPStack.IPv4v6

    async with AsyncExitStack() as exit_stack:
        [
            alpha_events,
            beta_events,
            gamma_events,
            alpha_expected_states,
            beta_expected_states,
            gamma_expected_states,
        ] = await run_default_scenario(
            exit_stack=exit_stack,
            alpha_is_local=True,
            beta_is_local=True,
            gamma_is_local=False,
            alpha_ip_stack=alpha_ip_stack,
            beta_ip_stack=beta_ip_stack,
            gamma_ip_stack=gamma_ip_stack,
        )

        assert alpha_events
        assert beta_events
        assert gamma_events

        alpha_validator = (
            basic_validator()
            .add_external_links_validator(
                exists=True,
                contains=["gamma_fingerprint"],
                does_not_contain=["vpn", alpha_events[0].fp, "alpha_fingerprint"],
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
                contains=["alpha_fingerprint", "beta_fingerprint"],
                does_not_contain=["gamma_fingerprint"],
            )
            .add_nat_type_validators(
                is_nat_type_collection_enabled=COLLECT_NAT_TYPE,
                nat_type="PortRestrictedCone",
                nat_mem=["PortRestrictedCone", "Symmetric"],
            )
        )

        assert alpha_validator.validate(alpha_events[0])

        beta_validator = (
            basic_validator()
            .add_external_links_validator(
                exists=True,
                contains=["gamma_fingerprint"],
                does_not_contain=["vpn", beta_events[0].fp, "beta_fingerprint"],
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
                contains=["alpha_fingerprint", "beta_fingerprint"],
                does_not_contain=["gamma_fingerprint"],
            )
            .add_nat_type_validators(
                is_nat_type_collection_enabled=COLLECT_NAT_TYPE,
                nat_type="PortRestrictedCone",
                nat_mem=["PortRestrictedCone", "Symmetric"],
            )
        )

        assert beta_validator.validate(beta_events[0])

        gamma_validator = (
            basic_validator(node_fingerprint="gamma_fingerprint")
            .add_external_links_validator(
                exists=True,
                contains=["alpha_fingerprint", "beta_fingerprint"],
                does_not_contain=["vpn", gamma_events[0].fp, "gamma_fingerprint"],
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
        )

        assert gamma_validator.validate(gamma_events[0])

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
        ] = await run_default_scenario(
            exit_stack=exit_stack,
            alpha_is_local=False,
            beta_is_local=False,
            gamma_is_local=False,
            alpha_ip_stack=alpha_ip_stack,
            beta_ip_stack=beta_ip_stack,
            gamma_ip_stack=gamma_ip_stack,
        )

        assert alpha_events
        assert beta_events
        assert gamma_events

        alpha_validator = (
            basic_validator(node_fingerprint="alpha_fingerprint")
            .add_external_links_validator(
                exists=True,
                contains=["beta_fingerprint", "gamma_fingerprint"],
                does_not_contain=["vpn", alpha_events[0].fp, "alpha_fingerprint"],
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
        )

        assert alpha_validator.validate(alpha_events[0])

        beta_validator = (
            basic_validator(node_fingerprint="beta_fingerprint")
            .add_external_links_validator(
                exists=True,
                contains=["alpha_fingerprint", "gamma_fingerprint"],
                does_not_contain=["vpn", beta_events[0].fp, "beta_fingerprint"],
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
        )

        assert beta_validator.validate(beta_events[0])

        gamma_validator = (
            basic_validator(node_fingerprint="gamma_fingerprint")
            .add_external_links_validator(
                exists=True,
                contains=["alpha_fingerprint", "beta_fingerprint"],
                does_not_contain=["vpn", gamma_events[0].fp, "gamma_fingerprint"],
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
        )

        assert gamma_validator.validate(gamma_events[0])

        # Validate all meshent ids are different
        assert alpha_events[0].fp != beta_events[0].fp
        assert alpha_events[0].fp != gamma_events[0].fp
        assert beta_events[0].fp != gamma_events[0].fp


@pytest.mark.moose
@pytest.mark.asyncio
@pytest.mark.parametrize("alpha_ip_stack,beta_ip_stack", IP_STACK_TEST_CONFIGS)
async def test_lana_with_vpn_connections(
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

        assert alpha_events
        assert beta_events
        assert gamma_events

        # Alpha has smallest public key when sorted lexicographically
        expected_meshnet_id = alpha_events[0].fp

        alpha_validator = (
            basic_validator(meshnet_id=expected_meshnet_id)
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
                contains=["alpha_fingerprint", "beta_fingerprint", "gamma_fingerprint"],
            )
            .add_nat_type_validators(
                is_nat_type_collection_enabled=COLLECT_NAT_TYPE,
                nat_type="Symmetric",
                nat_mem=["Symmetric", "PortRestrictedCone"],
            )
        )

        assert alpha_validator.validate(alpha_events[0])

        beta_validator = (
            basic_validator(meshnet_id=expected_meshnet_id)
            .add_external_links_validator(exists=False)
            .add_connectivity_matrix_validator(
                exists=True,
                no_of_connections=3,
                all_connections_up=False,
                expected_states=beta_expected_states,
            )
            .add_members_validator(
                exists=True,
                contains=["alpha_fingerprint", "beta_fingerprint", "gamma_fingerprint"],
            )
            .add_nat_type_validators(
                is_nat_type_collection_enabled=COLLECT_NAT_TYPE,
                nat_type="PortRestrictedCone",
                nat_mem=["Symmetric", "Symmetric"],
            )
        )

        assert beta_validator.validate(beta_events[0])

        gamma_validator = (
            basic_validator(meshnet_id=expected_meshnet_id)
            .add_external_links_validator(exists=False)
            .add_connectivity_matrix_validator(
                exists=True,
                no_of_connections=3,
                all_connections_up=False,
                expected_states=gamma_expected_states,
            )
            .add_members_validator(
                exists=True,
                contains=["alpha_fingerprint", "beta_fingerprint", "gamma_fingerprint"],
            )
            .add_nat_type_validators(
                is_nat_type_collection_enabled=COLLECT_NAT_TYPE,
                nat_type="Symmetric",
                nat_mem=["Symmetric", "PortRestrictedCone"],
            )
        )

        assert gamma_validator.validate(gamma_events[0])


@pytest.mark.moose
@pytest.mark.asyncio
@pytest.mark.xfail(reason="test is flaky - LLT-4451")
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
                ),
            )
        )
        (connection_beta, beta_conn_tracker) = await exit_stack.enter_async_context(
            new_connection_with_conn_tracker(
                ConnectionTag.DOCKER_CONE_CLIENT_2,
                generate_connection_tracker_config(
                    ConnectionTag.DOCKER_CONE_CLIENT_2,
                    derp_1_limits=ConnectionLimits(1, 1),
                ),
            )
        )

        await clean_container(connection_alpha)
        await clean_container(connection_beta)

        client_alpha = await exit_stack.enter_async_context(
            telio.Client(
                connection_alpha,
                alpha,
                telio_features=build_telio_features("alpha_fingerprint"),
            ).run(api.get_meshmap(alpha.id))
        )
        client_beta = await exit_stack.enter_async_context(
            telio.Client(
                connection_beta,
                beta,
                telio_features=build_telio_features("beta_fingerprint"),
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

        await asyncio.sleep(DEFAULT_WAITING_TIME)

        await client_alpha.trigger_event_collection()

        alpha_events = await wait_for_event_dump(
            ConnectionTag.DOCKER_CONE_CLIENT_1, ALPHA_EVENTS_PATH, nr_events=2
        )
        assert alpha_events

        alpha_validator = (
            basic_validator()
            .add_external_links_validator(exists=False)
            .add_connectivity_matrix_validator(
                exists=True,
                no_of_connections=1,
                all_connections_up=False,
                expected_states=[
                    (
                        DERP_BIT
                        | WG_BIT
                        | ip_stack_to_bits(
                            testing.unpack_optional(
                                choose_peer_stack(alpha_ip_stack, beta_ip_stack)
                            )
                        )
                    )
                ],
            )
            .add_members_validator(
                exists=True, contains=["alpha_fingerprint", "beta_fingerprint"]
            )
            .add_nat_type_validators(
                is_nat_type_collection_enabled=COLLECT_NAT_TYPE,
                nat_type="PortRestrictedCone",
                nat_mem=[],
            )
        )
        beta_validator = (
            basic_validator()
            .add_external_links_validator(exists=False)
            .add_connectivity_matrix_validator(
                exists=True,
                no_of_connections=1,
                all_connections_up=False,
                expected_states=[
                    (
                        DERP_BIT
                        | WG_BIT
                        | ip_stack_to_bits(
                            testing.unpack_optional(
                                choose_peer_stack(beta_ip_stack, alpha_ip_stack)
                            )
                        )
                    )
                ],
            )
            .add_members_validator(
                exists=True, contains=["alpha_fingerprint", "beta_fingerprint"]
            )
            .add_nat_type_validators(
                is_nat_type_collection_enabled=COLLECT_NAT_TYPE,
                nat_type="PortRestrictedCone",
                nat_mem=[],
            )
        )

        assert alpha_validator.validate(alpha_events[0])
        assert beta_validator.validate(beta_events[0])

        # Connectivity matrix is not persistent, will be missing when peer is offline
        alpha_validator = (
            basic_validator()
            .add_external_links_validator(exists=False)
            .add_connectivity_matrix_validator(exists=False)
            .add_members_validator(
                exists=True, contains=["alpha_fingerprint", "beta_fingerprint"]
            )
            .add_nat_type_validators(
                is_nat_type_collection_enabled=COLLECT_NAT_TYPE,
                nat_type="PortRestrictedCone",
                nat_mem=[],
            )
        )

        assert alpha_validator.validate(alpha_events[1])

        # Validate all nodes have the same meshnet id
        assert alpha_events[0].fp == alpha_events[1].fp == beta_events[0].fp
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
                telio_features=build_telio_features("beta_fingerprint"),
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
                telio_features=build_telio_features("alpha_fingerprint"),
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
                telio_features=build_telio_features("beta_fingerprint"),
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
                telio_features=build_telio_features("beta_fingerprint"),
            ).run(api.get_meshmap(beta.id))
        )

        await client_beta.trigger_event_collection()
        beta_events = await wait_for_event_dump(
            ConnectionTag.DOCKER_CONE_CLIENT_2, BETA_EVENTS_PATH, nr_events=1
        )
        assert beta_events
        second_beta_meshnet_id = beta_events[0].fp

        assert initial_beta_meshnet_id == second_beta_meshnet_id


@pytest.mark.moose
@pytest.mark.asyncio
@pytest.mark.parametrize(
    "initial_heartbeat_interval", [pytest.param(5), pytest.param(None)]
)
async def test_lana_initial_heartbeat_no_trigger(
    initial_heartbeat_interval: Optional[int],
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
                    "alpha_fingerprint",
                    initial_heartbeat_interval=initial_heartbeat_interval,
                ),
            ).run(api.get_meshmap(alpha.id))
        )

        if initial_heartbeat_interval:
            await asyncio.sleep(initial_heartbeat_interval)
            assert await wait_for_event_dump(
                ConnectionTag.DOCKER_CONE_CLIENT_1, ALPHA_EVENTS_PATH, nr_events=1
            )
        else:
            assert not await wait_for_event_dump(
                ConnectionTag.DOCKER_CONE_CLIENT_1, ALPHA_EVENTS_PATH, nr_events=1
            )
