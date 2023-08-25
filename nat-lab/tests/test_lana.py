import asyncio
import pytest
import subprocess
import telio
from config import WG_SERVER
from contextlib import AsyncExitStack
from mesh_api import API
from telio import PathType, Client
from telio_features import TelioFeatures, Nurse, Lana, Qos
from typing import Optional
from utils import testing
from utils.analytics import fetch_moose_events, basic_validator
from utils.connection_tracker import ConnectionLimits, ConnectionTracker
from utils.connection_util import (
    generate_connection_tracker_config,
    ConnectionTag,
    container_id,
    new_connection_with_conn_tracker,
    new_connection_by_tag,
)
from utils.ping import Ping

CONTAINER_EVENT_PATH = "/event.db"
ALPHA_EVENTS_PATH = "./alpha-events.db"
BETA_EVENTS_PATH = "./beta-events.db"
GAMMA_EVENTS_PATH = "./gamma-events.db"

DEFAULT_WAITING_TIME = 1
DEFAULT_CHECK_INTERVAL = 1
DEFAULT_CHECK_TIMEOUT = 40
COLLECT_NAT_TYPE = False


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


async def connect_to_default_vpn(client: Client, conn_tracker: ConnectionTracker):
    await testing.wait_long(
        asyncio.gather(
            client.connect_to_vpn(
                WG_SERVER["ipv4"], WG_SERVER["port"], WG_SERVER["public_key"]
            ),
            testing.wait_long(conn_tracker.wait_for_event("vpn_1")),
            client.wait_for_state_peer(
                WG_SERVER["public_key"], [telio.State.Connected], [PathType.Direct]
            ),
        )
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


async def run_default_scenario(
    exit_stack: AsyncExitStack,
    alpha_is_local,
    beta_is_local,
    gamma_is_local,
    alpha_has_vpn_connection=False,
    beta_has_vpn_connection=False,
    gamma_has_vpn_connection=False,
):
    api = API()
    (alpha, beta, gamma) = api.default_config_three_nodes(
        alpha_is_local=alpha_is_local,
        beta_is_local=beta_is_local,
        gamma_is_local=gamma_is_local,
    )

    (connection_alpha, alpha_conn_tracker) = await exit_stack.enter_async_context(
        new_connection_with_conn_tracker(
            ConnectionTag.DOCKER_CONE_CLIENT_1,
            generate_connection_tracker_config(
                ConnectionTag.DOCKER_CONE_CLIENT_1,
                # TODO: Change back derp limits max value to 1, when issue LLT-3875 is fixed
                derp_1_limits=ConnectionLimits(1, None),
                vpn_1_limits=ConnectionLimits(1 if alpha_has_vpn_connection else 0, 1),
            ),
        )
    )
    (connection_beta, beta_conn_tracker) = await exit_stack.enter_async_context(
        new_connection_with_conn_tracker(
            ConnectionTag.DOCKER_CONE_CLIENT_2,
            generate_connection_tracker_config(
                ConnectionTag.DOCKER_CONE_CLIENT_2,
                # TODO: Change back derp limits max value to 1, when issue LLT-3875 is fixed
                derp_1_limits=ConnectionLimits(1, None),
                vpn_1_limits=ConnectionLimits(1 if beta_has_vpn_connection else 0, 1),
            ),
        )
    )
    (connection_gamma, gamma_conn_tracker) = await exit_stack.enter_async_context(
        new_connection_with_conn_tracker(
            ConnectionTag.DOCKER_SYMMETRIC_CLIENT_1,
            generate_connection_tracker_config(
                ConnectionTag.DOCKER_SYMMETRIC_CLIENT_1,
                # TODO: Change back derp limits max value to 1, when issue LLT-3875 is fixed
                derp_1_limits=ConnectionLimits(1, None),
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
        ).run_meshnet(api.get_meshmap(alpha.id))
    )

    client_beta = await exit_stack.enter_async_context(
        telio.Client(
            connection_beta,
            beta,
            telio_features=build_telio_features("beta_fingerprint"),
        ).run_meshnet(api.get_meshmap(beta.id))
    )

    client_gamma = await exit_stack.enter_async_context(
        telio.Client(
            connection_gamma,
            gamma,
            telio_features=build_telio_features("gamma_fingerprint"),
        ).run_meshnet(api.get_meshmap(gamma.id))
    )

    await testing.wait_lengthy(
        asyncio.gather(
            client_alpha.wait_for_state_on_any_derp([telio.State.Connected]),
            client_beta.wait_for_state_on_any_derp([telio.State.Connected]),
            client_gamma.wait_for_state_on_any_derp([telio.State.Connected]),
            alpha_conn_tracker.wait_for_event("derp_1"),
            beta_conn_tracker.wait_for_event("derp_1"),
            gamma_conn_tracker.wait_for_event("derp_1"),
        )
    )
    await testing.wait_lengthy(
        asyncio.gather(
            client_alpha.wait_for_state_peer(beta.public_key, [telio.State.Connected]),
            client_alpha.wait_for_state_peer(gamma.public_key, [telio.State.Connected]),
            client_beta.wait_for_state_peer(alpha.public_key, [telio.State.Connected]),
            client_beta.wait_for_state_peer(gamma.public_key, [telio.State.Connected]),
            client_gamma.wait_for_state_peer(alpha.public_key, [telio.State.Connected]),
            client_gamma.wait_for_state_peer(beta.public_key, [telio.State.Connected]),
        )
    )

    if alpha_has_vpn_connection:
        await connect_to_default_vpn(client_alpha, alpha_conn_tracker)

    if beta_has_vpn_connection:
        await connect_to_default_vpn(client_beta, beta_conn_tracker)

    if gamma_has_vpn_connection:
        await connect_to_default_vpn(client_gamma, gamma_conn_tracker)

    async with Ping(connection_alpha, beta.ip_addresses[0]).run() as ping:
        await testing.wait_long(ping.wait_for_next_ping())
    async with Ping(connection_beta, gamma.ip_addresses[0]).run() as ping:
        await testing.wait_long(ping.wait_for_next_ping())
    async with Ping(connection_gamma, alpha.ip_addresses[0]).run() as ping:
        await testing.wait_long(ping.wait_for_next_ping())

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

    await testing.wait_long(
        asyncio.gather(
            client_alpha.stop_device(),
            client_beta.stop_device(),
            client_gamma.stop_device(),
        )
    )

    assert alpha_conn_tracker.get_out_of_limits() is None
    assert beta_conn_tracker.get_out_of_limits() is None
    assert gamma_conn_tracker.get_out_of_limits() is None

    return [alpha_events, beta_events, gamma_events]


@pytest.mark.moose
@pytest.mark.asyncio
async def test_lana_with_same_meshnet() -> None:
    async with AsyncExitStack() as exit_stack:
        [alpha_events, beta_events, gamma_events] = await run_default_scenario(
            exit_stack=exit_stack,
            alpha_is_local=True,
            beta_is_local=True,
            gamma_is_local=True,
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
                exists=True, no_of_connections=3, all_connections_up=True
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
                exists=True, no_of_connections=3, all_connections_up=True
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
                exists=True, no_of_connections=3, all_connections_up=True
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
async def test_lana_with_external_node() -> None:
    async with AsyncExitStack() as exit_stack:
        [alpha_events, beta_events, gamma_events] = await run_default_scenario(
            exit_stack=exit_stack,
            alpha_is_local=True,
            beta_is_local=True,
            gamma_is_local=False,
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
                all_connections_up=True,
                no_of_connections=1,
            )
            .add_connectivity_matrix_validator(
                exists=True, no_of_connections=1, all_connections_up=True
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
                all_connections_up=True,
                no_of_connections=1,
            )
            .add_connectivity_matrix_validator(
                exists=True, no_of_connections=1, all_connections_up=True
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
                all_connections_up=True,
                no_of_connections=2,
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
async def test_lana_all_external() -> None:
    async with AsyncExitStack() as exit_stack:
        [alpha_events, beta_events, gamma_events] = await run_default_scenario(
            exit_stack=exit_stack,
            alpha_is_local=False,
            beta_is_local=False,
            gamma_is_local=False,
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
                all_connections_up=True,
                no_of_connections=2,
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
                all_connections_up=True,
                no_of_connections=2,
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
                all_connections_up=True,
                no_of_connections=2,
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
async def test_lana_with_vpn_connections() -> None:
    async with AsyncExitStack() as exit_stack:
        [alpha_events, beta_events, gamma_events] = await run_default_scenario(
            exit_stack=exit_stack,
            alpha_is_local=True,
            beta_is_local=True,
            gamma_is_local=True,
            alpha_has_vpn_connection=True,
            beta_has_vpn_connection=False,
            gamma_has_vpn_connection=False,
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
                all_connections_up=True,
                no_of_connections=1,
                no_of_vpn=1,
            )
            .add_connectivity_matrix_validator(
                exists=True, no_of_connections=3, all_connections_up=True
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
                exists=True, no_of_connections=3, all_connections_up=True
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
                exists=True, no_of_connections=3, all_connections_up=True
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
async def test_lana_with_disconnected_node() -> None:
    async with AsyncExitStack() as exit_stack:
        api = API()
        (alpha, beta) = api.default_config_two_nodes(True, True)
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
                    # TODO: Change back derp limits max value to 1, when issue LLT-3875 is fixed
                    derp_1_limits=ConnectionLimits(1, None),
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
            ).run_meshnet(api.get_meshmap(alpha.id))
        )
        client_beta = await exit_stack.enter_async_context(
            telio.Client(
                connection_beta,
                beta,
                telio_features=build_telio_features("beta_fingerprint"),
            ).run_meshnet(api.get_meshmap(beta.id))
        )

        await testing.wait_long(
            asyncio.gather(
                client_alpha.wait_for_state_on_any_derp([telio.State.Connected]),
                client_beta.wait_for_state_on_any_derp([telio.State.Connected]),
                alpha_conn_tracker.wait_for_event("derp_1"),
                beta_conn_tracker.wait_for_event("derp_1"),
            )
        )
        await testing.wait_lengthy(
            asyncio.gather(
                client_alpha.wait_for_state_peer(
                    beta.public_key, [telio.State.Connected]
                ),
                client_beta.wait_for_state_peer(
                    alpha.public_key, [telio.State.Connected]
                ),
            )
        )

        async with Ping(connection_alpha, beta.ip_addresses[0]).run() as ping:
            await testing.wait_long(ping.wait_for_next_ping())

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
        await testing.wait_long(client_beta.stop_device())

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
                exists=True, no_of_connections=1, all_connections_up=True
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
                exists=True, no_of_connections=1, all_connections_up=True
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
@pytest.mark.xfail(reason="test is flaky - LLT-4187")
async def test_lana_with_second_node_joining_later_meshnet_id_can_change() -> None:
    async with AsyncExitStack() as exit_stack:
        api = API()
        beta = api.default_config_one_node(True)
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
            ).run_meshnet(api.get_meshmap(beta.id))
        )

        await client_beta.trigger_event_collection()
        beta_events = await wait_for_event_dump(
            ConnectionTag.DOCKER_CONE_CLIENT_2, BETA_EVENTS_PATH, nr_events=1
        )
        assert beta_events
        initial_beta_meshnet_id = beta_events[0].fp

        alpha = api.default_config_one_node(True)
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
            ).run_meshnet(api.get_meshmap(alpha.id))
        )

        beta.set_peer_firewall_settings(alpha.id, allow_incoming_connections=True)
        await client_beta.set_meshmap(api.get_meshmap(beta.id))

        await testing.wait_long(
            asyncio.gather(
                client_alpha.wait_for_state_peer(
                    beta.public_key, [telio.State.Connected]
                ),
                client_beta.wait_for_state_peer(
                    alpha.public_key, [telio.State.Connected]
                ),
            )
        )

        async with Ping(connection_alpha, beta.ip_addresses[0]).run() as ping:
            await testing.wait_long(ping.wait_for_next_ping())
        async with Ping(connection_beta, alpha.ip_addresses[0]).run() as ping:
            await testing.wait_long(ping.wait_for_next_ping())

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

        assert alpha_events[-1].fp != initial_beta_meshnet_id
        assert alpha_events[-1].fp == beta_events[-1].fp

        assert alpha_conn_tracker.get_out_of_limits() is None
        assert beta_conn_tracker.get_out_of_limits() is None


@pytest.mark.moose
@pytest.mark.asyncio
async def test_lana_same_meshnet_id_is_reported_after_a_restart():
    async with AsyncExitStack() as exit_stack:
        api = API()
        beta = api.default_config_one_node(True)
        connection_beta = await exit_stack.enter_async_context(
            new_connection_by_tag(ConnectionTag.DOCKER_CONE_CLIENT_2)
        )
        await clean_container(connection_beta)

        client_beta = await exit_stack.enter_async_context(
            telio.Client(
                connection_beta,
                beta,
                telio_features=build_telio_features("beta_fingerprint"),
            ).run_meshnet(api.get_meshmap(beta.id))
        )

        await client_beta.trigger_event_collection()
        beta_events = await wait_for_event_dump(
            ConnectionTag.DOCKER_CONE_CLIENT_2, BETA_EVENTS_PATH, nr_events=1
        )
        assert beta_events
        initial_beta_meshnet_id = beta_events[0].fp

        await client_beta.quit()
        api.remove(beta.id)

        beta = api.default_config_one_node(True)
        connection_beta = await exit_stack.enter_async_context(
            new_connection_by_tag(ConnectionTag.DOCKER_CONE_CLIENT_2)
        )

        client_beta = await exit_stack.enter_async_context(
            telio.Client(
                connection_beta,
                beta,
                telio_features=build_telio_features("beta_fingerprint"),
            ).run_meshnet(api.get_meshmap(beta.id))
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
            ).run_meshnet(api.get_meshmap(alpha.id))
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
