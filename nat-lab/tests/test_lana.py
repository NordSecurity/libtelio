from utils import Ping
from contextlib import AsyncExitStack
from config import ALPHA_NODE_ADDRESS, BETA_NODE_ADDRESS, GAMMA_NODE_ADDRESS, WG_SERVER
from mesh_api import API
from utils import ConnectionTag, new_connection_by_tag, container_id
from telio import PathType, Client
from telio_features import TelioFeatures, Nurse, Lana, Qos
from utils.analytics import fetch_moose_events, basic_validator
import asyncio
import pytest
import telio
import utils.testing as testing
import subprocess

CONTAINER_EVENT_PATH = "/event.db"
ALPHA_EVENTS_PATH = "./alpha-events.db"
BETA_EVENTS_PATH = "./beta-events.db"
GAMMA_EVENTS_PATH = "./gamma-events.db"

DEFAULT_WAITING_TIME = 1
DEFAULT_CHECK_INTERVAL = 1
DEFAULT_CHECK_TIMEOUT = 40


def build_telio_features(fingerprint: str) -> TelioFeatures:
    return TelioFeatures(
        lana=Lana(prod=False, event_path=CONTAINER_EVENT_PATH),
        nurse=Nurse(
            fingerprint=fingerprint,
            heartbeat_interval=3600,
            qos=Qos(
                rtt_interval=10,
                buckets=5,
            ),
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
        [
            "docker",
            "cp",
            container_id(container_tag) + ":" + container_path,
            local_path,
        ]
    )


async def connect_to_default_vpn(client: Client):
    await testing.wait_long(
        client.connect_to_vpn(
            WG_SERVER["ipv4"], WG_SERVER["port"], WG_SERVER["public_key"]
        )
    )
    await testing.wait_lengthy(
        client.handshake(WG_SERVER["public_key"], PathType.Direct)
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
    exit_stack,
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

    connection_alpha = await exit_stack.enter_async_context(
        new_connection_by_tag(ConnectionTag.DOCKER_CONE_CLIENT_1)
    )
    connection_beta = await exit_stack.enter_async_context(
        new_connection_by_tag(ConnectionTag.DOCKER_CONE_CLIENT_2)
    )
    connection_gamma = await exit_stack.enter_async_context(
        new_connection_by_tag(ConnectionTag.DOCKER_SYMMETRIC_CLIENT_1)
    )

    # Cleanup
    await clean_container(connection_alpha)
    await clean_container(connection_beta)
    await clean_container(connection_gamma)

    client_alpha = await exit_stack.enter_async_context(
        telio.run_meshnet(
            connection_alpha,
            alpha,
            api.get_meshmap(alpha.id),
            telio_features=build_telio_features("alpha_fingerprint"),
        )
    )

    client_beta = await exit_stack.enter_async_context(
        telio.run_meshnet(
            connection_beta,
            beta,
            api.get_meshmap(beta.id),
            telio_features=build_telio_features("beta_fingerprint"),
        )
    )

    client_gamma = await exit_stack.enter_async_context(
        telio.run_meshnet(
            connection_gamma,
            gamma,
            api.get_meshmap(gamma.id),
            telio_features=build_telio_features("gamma_fingerprint"),
        )
    )

    await testing.wait_long(client_alpha.handshake(beta.public_key))
    await testing.wait_long(client_alpha.handshake(gamma.public_key))
    await testing.wait_long(client_beta.handshake(gamma.public_key))

    if alpha_has_vpn_connection:
        await connect_to_default_vpn(client_alpha)

    if beta_has_vpn_connection:
        await connect_to_default_vpn(client_beta)

    if gamma_has_vpn_connection:
        await connect_to_default_vpn(client_gamma)

    async with Ping(connection_alpha, BETA_NODE_ADDRESS) as ping:
        await testing.wait_long(ping.wait_for_next_ping())
    async with Ping(connection_beta, GAMMA_NODE_ADDRESS) as ping:
        await testing.wait_long(ping.wait_for_next_ping())
    async with Ping(connection_gamma, ALPHA_NODE_ADDRESS) as ping:
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

    await testing.wait_long(client_alpha.stop_device())
    await testing.wait_long(client_beta.stop_device())
    await testing.wait_long(client_gamma.stop_device())

    return [alpha_events, beta_events, gamma_events]


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

        alpha_validator = (
            basic_validator()
            .add_external_links_validator(exists=False)
            .add_connectivity_matrix_validator(
                exists=True,
                no_of_connections=3,
                all_connections_up=True,
            )
            .add_members_validator(
                exists=True,
                contains=["alpha_fingerprint", "beta_fingerprint", "gamma_fingerprint"],
            )
        )

        assert alpha_validator.validate(alpha_events[0])

        beta_validator = (
            basic_validator()
            .add_external_links_validator(exists=False)
            .add_connectivity_matrix_validator(
                exists=True,
                no_of_connections=3,
                all_connections_up=True,
            )
            .add_members_validator(
                exists=True,
                contains=["alpha_fingerprint", "beta_fingerprint", "gamma_fingerprint"],
            )
        )
        assert beta_validator.validate(beta_events[0])

        gamma_validator = (
            basic_validator()
            .add_external_links_validator(exists=False)
            .add_connectivity_matrix_validator(
                exists=True,
                no_of_connections=3,
                all_connections_up=True,
            )
            .add_members_validator(
                exists=True,
                contains=["alpha_fingerprint", "beta_fingerprint", "gamma_fingerprint"],
            )
        )
        assert gamma_validator.validate(gamma_events[0])

        # Validate all nodes have the same meshnet id
        assert alpha_events[0].fp == beta_events[0].fp
        assert beta_events[0].fp == gamma_events[0].fp


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
                exists=True,
                no_of_connections=1,
                all_connections_up=True,
            )
            .add_members_validator(
                exists=True,
                contains=["alpha_fingerprint", "beta_fingerprint"],
                does_not_contain=["gamma_fingerprint"],
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
                exists=True,
                no_of_connections=1,
                all_connections_up=True,
            )
            .add_members_validator(
                exists=True,
                contains=["alpha_fingerprint", "beta_fingerprint"],
                does_not_contain=["gamma_fingerprint"],
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
        )
        assert gamma_validator.validate(gamma_events[0])

        # Validate alpha and beta have the same meshent id which is different from gamma's
        assert alpha_events[0].fp == beta_events[0].fp
        assert alpha_events[0].fp != gamma_events[0].fp


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
        )
        assert gamma_validator.validate(gamma_events[0])

        # Validate all meshent ids are different
        assert alpha_events[0].fp != beta_events[0].fp
        assert alpha_events[0].fp != gamma_events[0].fp
        assert beta_events[0].fp != gamma_events[0].fp


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

        alpha_validator = (
            basic_validator()
            .add_external_links_validator(
                exists=True,
                contains=["vpn"],
                all_connections_up=True,
                no_of_connections=1,
                no_of_vpn=1,
            )
            .add_connectivity_matrix_validator(
                exists=True,
                no_of_connections=3,
                all_connections_up=True,
            )
            .add_members_validator(
                exists=True,
                contains=["alpha_fingerprint", "beta_fingerprint", "gamma_fingerprint"],
            )
        )
        assert alpha_validator.validate(alpha_events[0])

        beta_validator = (
            basic_validator()
            .add_external_links_validator(exists=False)
            .add_connectivity_matrix_validator(
                exists=True,
                no_of_connections=3,
                all_connections_up=True,
            )
            .add_members_validator(
                exists=True,
                contains=["alpha_fingerprint", "beta_fingerprint", "gamma_fingerprint"],
            )
        )
        assert beta_validator.validate(beta_events[0])

        gamma_validator = (
            basic_validator()
            .add_external_links_validator(exists=False)
            .add_connectivity_matrix_validator(
                exists=True,
                no_of_connections=3,
                all_connections_up=True,
            )
            .add_members_validator(
                exists=True,
                contains=["alpha_fingerprint", "beta_fingerprint", "gamma_fingerprint"],
            )
        )
        assert gamma_validator.validate(gamma_events[0])

        # Validate all nodes have the same meshnet id
        assert alpha_events[0].fp == beta_events[0].fp
        assert beta_events[0].fp == gamma_events[0].fp


@pytest.mark.asyncio
async def test_lana_with_disconnected_node() -> None:
    async with AsyncExitStack() as exit_stack:
        api = API()
        alpha = api.register(
            name="alpha",
            id="96ddb926-4b86-11ec-81d3-0242ac130003",
            private_key="IGm+42FLMMGZRaQvk6F3UPbl+T/CBk8W+NPoX2/AdlU=",
            public_key="41CCEssnYIh8/8D8YvbTfWEcFanG3D0I0z1tRcN1Lyc=",
            is_local=True,
        )

        beta = api.register(
            name="beta",
            id="7b4548ca-fe5a-4597-8513-896f38c6d6ae",
            private_key="SPFD84gPtBNc3iGY9Cdrj+mSCwBeh3mCMWfPaeWQolw=",
            public_key="Q1M3VKUcfTmGsrRzY6BpNds1yDIUvPVcs/2TySv/t1U=",
            is_local=True,
        )

        api.assign_ip(alpha.id, ALPHA_NODE_ADDRESS)
        api.assign_ip(beta.id, BETA_NODE_ADDRESS)

        alpha.set_peer_firewall_settings(beta.id, allow_incoming_connections=True)
        beta.set_peer_firewall_settings(alpha.id, allow_incoming_connections=True)

        connection_alpha = await exit_stack.enter_async_context(
            new_connection_by_tag(ConnectionTag.DOCKER_CONE_CLIENT_1)
        )
        connection_beta = await exit_stack.enter_async_context(
            new_connection_by_tag(ConnectionTag.DOCKER_CONE_CLIENT_2)
        )

        await clean_container(connection_alpha)
        await clean_container(connection_beta)

        client_alpha = await exit_stack.enter_async_context(
            telio.run_meshnet(
                connection_alpha,
                alpha,
                api.get_meshmap(alpha.id),
                telio_features=build_telio_features("alpha_fingerprint"),
            )
        )
        client_beta = await exit_stack.enter_async_context(
            telio.run_meshnet(
                connection_beta,
                beta,
                api.get_meshmap(beta.id),
                telio_features=build_telio_features("beta_fingerprint"),
            )
        )

        await testing.wait_long(client_alpha.handshake(beta.public_key))

        async with Ping(connection_alpha, beta.ip_addresses[0]) as ping:
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
                exists=True,
                no_of_connections=1,
                all_connections_up=True,
            )
            .add_members_validator(
                exists=True,
                contains=["alpha_fingerprint", "beta_fingerprint"],
            )
        )
        beta_validator = (
            basic_validator()
            .add_external_links_validator(exists=False)
            .add_connectivity_matrix_validator(
                exists=True,
                no_of_connections=1,
                all_connections_up=True,
            )
            .add_members_validator(
                exists=True,
                contains=["alpha_fingerprint", "beta_fingerprint"],
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
                exists=True,
                contains=["alpha_fingerprint", "beta_fingerprint"],
            )
        )
        assert alpha_validator.validate(alpha_events[1])

        # Validate all nodes have the same meshnet id
        assert alpha_events[0].fp == alpha_events[1].fp == beta_events[0].fp
