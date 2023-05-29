from utils import Ping
from config import DERP_PRIMARY, DERP_SECONDARY, DERP_TERTIARY
from contextlib import AsyncExitStack
from mesh_api import API
from utils import ConnectionTag, new_connection_by_tag, testing
from derp_cli import check_derp_connection
from telio import PathType
from telio_features import TelioFeatures, Direct
import asyncio
import pytest
import telio

ANY_PROVIDERS = ["local", "stun"]
LOCAL_PROVIDER = ["local"]
STUN_PROVIDER = ["stun"]

DOCKER_CONE_GW_2_IP = "10.0.254.2"
DOCKER_FULLCONE_GW_1_IP = "10.0.254.9"
DOCKER_FULLCONE_GW_2_IP = "10.0.254.6"
DOCKER_OPEN_INTERNET_CLIENT_1_IP = "10.0.11.2"
DOCKER_OPEN_INTERNET_CLIENT_2_IP = "10.0.11.3"
DOCKER_SYMMETRIC_GW_1_IP = "10.0.254.3"

UHP_conn_client_types = [
    (
        STUN_PROVIDER,
        ConnectionTag.DOCKER_FULLCONE_CLIENT_1,
        ConnectionTag.DOCKER_FULLCONE_CLIENT_2,
        DOCKER_FULLCONE_GW_2_IP,
    ),
    (
        STUN_PROVIDER,
        ConnectionTag.DOCKER_SYMMETRIC_CLIENT_1,
        ConnectionTag.DOCKER_FULLCONE_CLIENT_1,
        DOCKER_SYMMETRIC_GW_1_IP,
    ),
    (
        STUN_PROVIDER,
        ConnectionTag.DOCKER_OPEN_INTERNET_CLIENT_1,
        ConnectionTag.DOCKER_FULLCONE_CLIENT_1,
        DOCKER_FULLCONE_GW_1_IP,
    ),
    (
        STUN_PROVIDER,
        ConnectionTag.DOCKER_CONE_CLIENT_1,
        ConnectionTag.DOCKER_FULLCONE_CLIENT_1,
        DOCKER_FULLCONE_GW_1_IP,
    ),
    (
        STUN_PROVIDER,
        ConnectionTag.DOCKER_CONE_CLIENT_1,
        ConnectionTag.DOCKER_CONE_CLIENT_2,
        DOCKER_CONE_GW_2_IP,
    ),
    (
        STUN_PROVIDER,
        ConnectionTag.DOCKER_CONE_CLIENT_1,
        ConnectionTag.DOCKER_OPEN_INTERNET_CLIENT_1,
        DOCKER_OPEN_INTERNET_CLIENT_1_IP,
    ),
    (
        LOCAL_PROVIDER,
        ConnectionTag.DOCKER_OPEN_INTERNET_CLIENT_1,
        ConnectionTag.DOCKER_OPEN_INTERNET_CLIENT_2,
        DOCKER_OPEN_INTERNET_CLIENT_2_IP,
    ),
    (
        STUN_PROVIDER,
        ConnectionTag.DOCKER_OPEN_INTERNET_CLIENT_1,
        ConnectionTag.DOCKER_OPEN_INTERNET_CLIENT_2,
        DOCKER_OPEN_INTERNET_CLIENT_2_IP,
    ),
    (
        STUN_PROVIDER,
        ConnectionTag.DOCKER_SYMMETRIC_CLIENT_1,
        ConnectionTag.DOCKER_OPEN_INTERNET_CLIENT_1,
        DOCKER_OPEN_INTERNET_CLIENT_1_IP,
    ),
]


@pytest.mark.asyncio
@pytest.mark.timeout(150)
@pytest.mark.parametrize(
    "endpoint_providers, client1_type, client2_type, reflexive_ip",
    UHP_conn_client_types,
)
async def test_direct_working_paths(
    endpoint_providers, client1_type, client2_type, reflexive_ip
) -> None:
    async with AsyncExitStack() as exit_stack:
        DERP_IP = str(DERP_PRIMARY["ipv4"])
        CLIENT_ALPHA_IP = "100.72.31.21"
        CLIENT_BETA_IP = "100.72.31.22"

        api = API()
        alpha = api.register(
            name="alpha",
            id="96ddb926-4b86-11ec-81d3-0242ac130003",
            private_key="IGm+42FLMMGZRaQvk6F3UPbl+T/CBk8W+NPoX2/AdlU=",
            public_key="41CCEssnYIh8/8D8YvbTfWEcFanG3D0I0z1tRcN1Lyc=",
        )
        beta = api.register(
            name="beta",
            id="7b4548ca-fe5a-4597-8513-896f38c6d6ae",
            private_key="SPFD84gPtBNc3iGY9Cdrj+mSCwBeh3mCMWfPaeWQolw=",
            public_key="Q1M3VKUcfTmGsrRzY6BpNds1yDIUvPVcs/2TySv/t1U=",
        )
        api.assign_ip(alpha.id, CLIENT_ALPHA_IP)
        api.assign_ip(beta.id, CLIENT_BETA_IP)

        # create a rule in  iptables to accept connections
        beta.set_peer_firewall_settings(alpha.id, allow_incoming_connections=True)
        alpha.set_peer_firewall_settings(beta.id, allow_incoming_connections=True)

        alpha_connection = await exit_stack.enter_async_context(
            new_connection_by_tag(client1_type)
        )

        beta_connection = await exit_stack.enter_async_context(
            new_connection_by_tag(client2_type)
        )

        alpha_client = await exit_stack.enter_async_context(
            telio.run_meshnet(
                alpha_connection,
                alpha,
                api.get_meshmap(alpha.id),
                telio.AdapterType.BoringTun,
                telio_features=TelioFeatures(
                    direct=Direct(providers=endpoint_providers)
                ),
            )
        )

        beta_client = await exit_stack.enter_async_context(
            telio.run_meshnet(
                beta_connection,
                beta,
                api.get_meshmap(beta.id),
                telio.AdapterType.BoringTun,
                telio_features=TelioFeatures(
                    direct=Direct(providers=endpoint_providers)
                ),
            )
        )

        await testing.wait_lengthy(check_derp_connection(alpha_client, DERP_IP, True))
        await testing.wait_lengthy(check_derp_connection(beta_client, DERP_IP, True))

        await testing.wait_lengthy(
            alpha_client._events.wait_for_state(
                "Q1M3VKUcfTmGsrRzY6BpNds1yDIUvPVcs/2TySv/t1U=",
                telio.State.Connected,
                PathType.Direct,
            ),
        )
        await testing.wait_lengthy(
            beta_client._events.wait_for_state(
                "41CCEssnYIh8/8D8YvbTfWEcFanG3D0I0z1tRcN1Lyc=",
                telio.State.Connected,
                PathType.Direct,
            )
        )

        for ip in [
            str(DERP_PRIMARY["ipv4"]),
            str(DERP_SECONDARY["ipv4"]),
            str(DERP_TERTIARY["ipv4"]),
        ]:
            await exit_stack.enter_async_context(
                alpha_client.get_router().break_tcp_conn_to_host(ip)
            )
            await exit_stack.enter_async_context(
                beta_client.get_router().break_tcp_conn_to_host(ip)
            )

        async with Ping(alpha_connection, CLIENT_BETA_IP) as ping:
            await testing.wait_long(ping.wait_for_next_ping())


@pytest.mark.asyncio
@pytest.mark.timeout(150)
@pytest.mark.parametrize(
    "endpoint_providers, client1_type, client2_type",
    [
        (
            ANY_PROVIDERS,
            ConnectionTag.DOCKER_CONE_CLIENT_1,
            ConnectionTag.DOCKER_SYMMETRIC_CLIENT_1,
        ),
        (
            ANY_PROVIDERS,
            ConnectionTag.DOCKER_CONE_CLIENT_1,
            ConnectionTag.DOCKER_UDP_BLOCK_CLIENT_1,
        ),
        (
            ANY_PROVIDERS,
            ConnectionTag.DOCKER_SYMMETRIC_CLIENT_1,
            ConnectionTag.DOCKER_SYMMETRIC_CLIENT_2,
        ),
        (
            ANY_PROVIDERS,
            ConnectionTag.DOCKER_SYMMETRIC_CLIENT_1,
            ConnectionTag.DOCKER_UDP_BLOCK_CLIENT_1,
        ),
        (
            ANY_PROVIDERS,
            ConnectionTag.DOCKER_OPEN_INTERNET_CLIENT_1,
            ConnectionTag.DOCKER_UDP_BLOCK_CLIENT_1,
        ),
        (
            ANY_PROVIDERS,
            ConnectionTag.DOCKER_UDP_BLOCK_CLIENT_1,
            ConnectionTag.DOCKER_UDP_BLOCK_CLIENT_2,
        ),
        (
            LOCAL_PROVIDER,
            ConnectionTag.DOCKER_OPEN_INTERNET_CLIENT_1,
            ConnectionTag.DOCKER_FULLCONE_CLIENT_1,
        ),
        (
            LOCAL_PROVIDER,
            ConnectionTag.DOCKER_CONE_CLIENT_1,
            ConnectionTag.DOCKER_OPEN_INTERNET_CLIENT_1,
        ),
        (
            LOCAL_PROVIDER,
            ConnectionTag.DOCKER_SYMMETRIC_CLIENT_1,
            ConnectionTag.DOCKER_OPEN_INTERNET_CLIENT_1,
        ),
    ],
)
@pytest.mark.skip(
    reason="Negative cases need to be refactored to check if it's actual direct, relay can no longer be easily avoided"
)
async def test_direct_failing_paths(
    endpoint_providers, client1_type, client2_type
) -> None:
    async with AsyncExitStack() as exit_stack:
        DERP_IP = str(DERP_PRIMARY["ipv4"])
        CLIENT_ALPHA_IP = "100.72.31.21"
        CLIENT_BETA_IP = "100.72.31.22"

        api = API()
        alpha = api.register(
            name="alpha",
            id="96ddb926-4b86-11ec-81d3-0242ac130003",
            private_key="IGm+42FLMMGZRaQvk6F3UPbl+T/CBk8W+NPoX2/AdlU=",
            public_key="41CCEssnYIh8/8D8YvbTfWEcFanG3D0I0z1tRcN1Lyc=",
        )
        beta = api.register(
            name="beta",
            id="7b4548ca-fe5a-4597-8513-896f38c6d6ae",
            private_key="SPFD84gPtBNc3iGY9Cdrj+mSCwBeh3mCMWfPaeWQolw=",
            public_key="Q1M3VKUcfTmGsrRzY6BpNds1yDIUvPVcs/2TySv/t1U=",
        )
        api.assign_ip(alpha.id, CLIENT_ALPHA_IP)
        api.assign_ip(beta.id, CLIENT_BETA_IP)

        # create a rule in  iptables to accept connections
        beta.set_peer_firewall_settings(alpha.id, allow_incoming_connections=True)
        alpha.set_peer_firewall_settings(beta.id, allow_incoming_connections=True)

        alpha_connection = await exit_stack.enter_async_context(
            new_connection_by_tag(client1_type)
        )

        beta_connection = await exit_stack.enter_async_context(
            new_connection_by_tag(client2_type)
        )

        alpha_client = await exit_stack.enter_async_context(
            telio.run_meshnet(
                alpha_connection,
                alpha,
                api.get_meshmap(alpha.id),
                telio.AdapterType.BoringTun,
                telio_features=TelioFeatures(
                    direct=Direct(providers=endpoint_providers)
                ),
            )
        )

        beta_client = await exit_stack.enter_async_context(
            telio.run_meshnet(
                beta_connection,
                beta,
                api.get_meshmap(beta.id),
                telio.AdapterType.BoringTun,
                telio_features=TelioFeatures(
                    direct=Direct(providers=endpoint_providers)
                ),
            )
        )

        await testing.wait_lengthy(check_derp_connection(alpha_client, DERP_IP, True))
        await testing.wait_lengthy(check_derp_connection(beta_client, DERP_IP, True))

        # TODO: Add CMM messages are going through
        with pytest.raises(asyncio.TimeoutError):
            async with Ping(alpha_connection, CLIENT_BETA_IP) as ping:
                await testing.wait_long(ping.wait_for_next_ping())


@pytest.mark.asyncio
@pytest.mark.long
@pytest.mark.parametrize(
    "endpoint_providers, client1_type, client2_type, reflexive_ip",
    UHP_conn_client_types,
)
@pytest.mark.timeout(4 * 60)
@pytest.mark.skip(reason="Test will need to be adapted for direct in the future")
async def test_direct_short_connection_loss(
    endpoint_providers, client1_type, client2_type, reflexive_ip
) -> None:
    async with AsyncExitStack() as exit_stack:
        CLIENT_ALPHA_IP = "100.72.31.21"
        CLIENT_BETA_IP = "100.72.31.22"

        api = API()
        alpha = api.register(
            name="alpha",
            id="96ddb926-4b86-11ec-81d3-0242ac130003",
            private_key="IGm+42FLMMGZRaQvk6F3UPbl+T/CBk8W+NPoX2/AdlU=",
            public_key="41CCEssnYIh8/8D8YvbTfWEcFanG3D0I0z1tRcN1Lyc=",
        )
        beta = api.register(
            name="beta",
            id="7b4548ca-fe5a-4597-8513-896f38c6d6ae",
            private_key="SPFD84gPtBNc3iGY9Cdrj+mSCwBeh3mCMWfPaeWQolw=",
            public_key="Q1M3VKUcfTmGsrRzY6BpNds1yDIUvPVcs/2TySv/t1U=",
        )
        api.assign_ip(alpha.id, CLIENT_ALPHA_IP)
        api.assign_ip(beta.id, CLIENT_BETA_IP)

        # create a rule in  iptables to accept connections
        beta.set_peer_firewall_settings(alpha.id, allow_incoming_connections=True)
        alpha.set_peer_firewall_settings(beta.id, allow_incoming_connections=True)

        alpha_connection = await exit_stack.enter_async_context(
            new_connection_by_tag(client1_type)
        )

        beta_connection = await exit_stack.enter_async_context(
            new_connection_by_tag(client2_type)
        )

        alpha_client = await exit_stack.enter_async_context(
            telio.run_meshnet(
                alpha_connection,
                alpha,
                api.get_meshmap(alpha.id),
                telio.AdapterType.BoringTun,
                telio_features=TelioFeatures(
                    direct=Direct(providers=endpoint_providers)
                ),
            )
        )

        beta_client = await exit_stack.enter_async_context(
            telio.run_meshnet(
                beta_connection,
                beta,
                api.get_meshmap(beta.id),
                telio.AdapterType.BoringTun,
                telio_features=TelioFeatures(
                    direct=Direct(providers=endpoint_providers)
                ),
            )
        )

        await testing.wait_defined(
            alpha_client._events.wait_for_state(
                "Q1M3VKUcfTmGsrRzY6BpNds1yDIUvPVcs/2TySv/t1U=",
                telio.State.Connected,
                PathType.Direct,
            ),
            120,
        )
        await testing.wait_lengthy(
            beta_client._events.wait_for_state(
                "41CCEssnYIh8/8D8YvbTfWEcFanG3D0I0z1tRcN1Lyc=",
                telio.State.Connected,
                PathType.Direct,
            )
        )

        # Disrupt UHP connection for 25 seconds
        await alpha_connection.create_process(
            [
                "iptables",
                "-t",
                "filter",
                "-A",
                "OUTPUT",
                "-d",
                reflexive_ip,
                "-j",
                "DROP",
            ]
        ).execute()
        await asyncio.sleep(25)

        with pytest.raises(asyncio.TimeoutError):
            async with Ping(alpha_connection, CLIENT_BETA_IP) as ping:
                await testing.wait_short(ping.wait_for_next_ping())

        await alpha_connection.create_process(
            [
                "iptables",
                "-t",
                "filter",
                "-D",
                "OUTPUT",
                "-d",
                reflexive_ip,
                "-j",
                "DROP",
            ]
        ).execute()

        async with Ping(alpha_connection, CLIENT_BETA_IP) as ping:
            await testing.wait_lengthy(ping.wait_for_next_ping())


@pytest.mark.asyncio
@pytest.mark.long
@pytest.mark.parametrize(
    "endpoint_providers, client1_type, client2_type, reflexive_ip",
    UHP_conn_client_types,
)
@pytest.mark.timeout(4 * 60)
@pytest.mark.skip(reason="the test is flaky - JIRA issue: LLT-3079")
async def test_direct_connection_loss_for_infinity(
    endpoint_providers, client1_type, client2_type, reflexive_ip
) -> None:
    async with AsyncExitStack() as exit_stack:
        CLIENT_ALPHA_IP = "100.72.31.21"
        CLIENT_BETA_IP = "100.72.31.22"

        api = API()
        alpha = api.register(
            name="alpha",
            id="96ddb926-4b86-11ec-81d3-0242ac130003",
            private_key="IGm+42FLMMGZRaQvk6F3UPbl+T/CBk8W+NPoX2/AdlU=",
            public_key="41CCEssnYIh8/8D8YvbTfWEcFanG3D0I0z1tRcN1Lyc=",
        )
        beta = api.register(
            name="beta",
            id="7b4548ca-fe5a-4597-8513-896f38c6d6ae",
            private_key="SPFD84gPtBNc3iGY9Cdrj+mSCwBeh3mCMWfPaeWQolw=",
            public_key="Q1M3VKUcfTmGsrRzY6BpNds1yDIUvPVcs/2TySv/t1U=",
        )
        api.assign_ip(alpha.id, CLIENT_ALPHA_IP)
        api.assign_ip(beta.id, CLIENT_BETA_IP)

        # create a rule in  iptables to accept connections
        beta.set_peer_firewall_settings(alpha.id, allow_incoming_connections=True)
        alpha.set_peer_firewall_settings(beta.id, allow_incoming_connections=True)

        alpha_connection = await exit_stack.enter_async_context(
            new_connection_by_tag(client1_type)
        )

        beta_connection = await exit_stack.enter_async_context(
            new_connection_by_tag(client2_type)
        )

        alpha_client = await exit_stack.enter_async_context(
            telio.run_meshnet(
                alpha_connection,
                alpha,
                api.get_meshmap(alpha.id),
                telio.AdapterType.BoringTun,
                telio_features=TelioFeatures(
                    direct=Direct(providers=endpoint_providers)
                ),
            )
        )

        beta_client = await exit_stack.enter_async_context(
            telio.run_meshnet(
                beta_connection,
                beta,
                api.get_meshmap(beta.id),
                telio.AdapterType.BoringTun,
                telio_features=TelioFeatures(
                    direct=Direct(providers=endpoint_providers)
                ),
            )
        )

        await testing.wait_defined(
            alpha_client._events.wait_for_state(
                "Q1M3VKUcfTmGsrRzY6BpNds1yDIUvPVcs/2TySv/t1U=",
                telio.State.Connected,
                PathType.Direct,
            ),
            120,
        )
        await testing.wait_lengthy(
            beta_client._events.wait_for_state(
                "41CCEssnYIh8/8D8YvbTfWEcFanG3D0I0z1tRcN1Lyc=",
                telio.State.Connected,
                PathType.Direct,
            )
        )

        await alpha_connection.create_process(
            [
                "iptables",
                "-t",
                "filter",
                "-A",
                "OUTPUT",
                "-d",
                reflexive_ip,
                "-j",
                "DROP",
            ]
        ).execute()

        with pytest.raises(asyncio.TimeoutError):
            async with Ping(alpha_connection, CLIENT_BETA_IP) as ping:
                await testing.wait_short(ping.wait_for_next_ping())

        await testing.wait_defined(
            alpha_client._events.wait_for_state(
                "Q1M3VKUcfTmGsrRzY6BpNds1yDIUvPVcs/2TySv/t1U=",
                telio.State.Connected,
                PathType.Relay,
            ),
            120,
        )
        await testing.wait_lengthy(
            beta_client._events.wait_for_state(
                "41CCEssnYIh8/8D8YvbTfWEcFanG3D0I0z1tRcN1Lyc=",
                telio.State.Connected,
                PathType.Relay,
            )
        )

        async with Ping(alpha_connection, CLIENT_BETA_IP) as ping:
            await testing.wait_lengthy(ping.wait_for_next_ping())

        await alpha_connection.create_process(
            [
                "iptables",
                "-t",
                "filter",
                "-D",
                "OUTPUT",
                "-d",
                reflexive_ip,
                "-j",
                "DROP",
            ]
        ).execute()
