import asyncio
from contextlib import AsyncExitStack
from utils import Ping, new_router
import pytest
import telio
import utils.testing as testing
from mesh_api import API, DERP_SERVERS
from telio_features import TelioFeatures, Direct
from utils import ConnectionTag, new_connection_by_tag, new_connection_raw


@pytest.mark.asyncio
async def test_direct_upnp_connection() -> None:
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
            new_connection_by_tag(ConnectionTag.DOCKER_UPNP_CLIENT_1)
        )
        beta_connection = await exit_stack.enter_async_context(
            new_connection_by_tag(ConnectionTag.DOCKER_UPNP_CLIENT_2)
        )

        alpha_client = await exit_stack.enter_async_context(
            telio.run_meshnet(
                alpha_connection,
                alpha,
                api.get_meshmap(alpha.id),
                telio.AdapterType.BoringTun,
                telio_features=TelioFeatures(direct=Direct(providers=["upnp"])),
            )
        )

        beta_client = await exit_stack.enter_async_context(
            telio.run_meshnet(
                beta_connection,
                beta,
                api.get_meshmap(beta.id),
                telio.AdapterType.BoringTun,
                telio_features=TelioFeatures(direct=Direct(providers=["upnp"])),
            )
        )

        await asyncio.gather(
            testing.wait_lengthy(
                alpha_client.wait_for_any_derp_state([telio.State.Connected])
            ),
            testing.wait_lengthy(
                beta_client.wait_for_any_derp_state([telio.State.Connected])
            ),
        )

        await asyncio.gather(
            testing.wait_lengthy(
                alpha_client.handshake(
                    beta.public_key,
                    telio.PathType.Direct,
                )
            ),
            testing.wait_lengthy(
                beta_client.handshake(
                    alpha.public_key,
                    telio.PathType.Direct,
                )
            ),
        )

        for derp in DERP_SERVERS:
            await exit_stack.enter_async_context(
                alpha_client.get_router().break_tcp_conn_to_host(str(derp["ipv4"]))
            )
            await exit_stack.enter_async_context(
                beta_client.get_router().break_tcp_conn_to_host(str(derp["ipv4"]))
            )

        async with Ping(alpha_connection, CLIENT_BETA_IP) as ping:
            await testing.wait_defined(ping.wait_for_next_ping(), 40)


@pytest.mark.timeout(180)
@pytest.mark.asyncio
async def test_direct_upnp_connection_endpoint_gone() -> None:
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

        beta.set_peer_firewall_settings(alpha.id, allow_incoming_connections=True)
        alpha.set_peer_firewall_settings(beta.id, allow_incoming_connections=True)

        alpha_connection = await exit_stack.enter_async_context(
            new_connection_by_tag(ConnectionTag.DOCKER_UPNP_CLIENT_1)
        )
        beta_connection = await exit_stack.enter_async_context(
            new_connection_by_tag(ConnectionTag.DOCKER_UPNP_CLIENT_2)
        )

        alpha_client = await exit_stack.enter_async_context(
            telio.run_meshnet(
                alpha_connection,
                alpha,
                api.get_meshmap(alpha.id),
                telio_features=TelioFeatures(
                    direct=Direct(providers=["upnp"], endpoint_interval_secs=10)
                ),
            )
        )

        beta_client = await exit_stack.enter_async_context(
            telio.run_meshnet(
                beta_connection,
                beta,
                api.get_meshmap(beta.id),
                telio_features=TelioFeatures(
                    direct=Direct(providers=["upnp"], endpoint_interval_secs=10)
                ),
            )
        )

        async def _check_if_true_direct_connection() -> None:
            async with AsyncExitStack() as temp_exit_stack:
                for derp in DERP_SERVERS:
                    await temp_exit_stack.enter_async_context(
                        alpha_client.get_router().break_tcp_conn_to_host(
                            str(derp["ipv4"])
                        )
                    )
                    await temp_exit_stack.enter_async_context(
                        beta_client.get_router().break_tcp_conn_to_host(
                            str(derp["ipv4"])
                        )
                    )

                await asyncio.gather(
                    testing.wait_defined(
                        alpha_client.wait_for_any_derp_state(
                            [telio.State.Connecting, telio.State.Disconnected],
                            wait_for_repeating_event=True,
                        ),
                        60,
                    ),
                    testing.wait_defined(
                        beta_client.wait_for_any_derp_state(
                            [telio.State.Connecting, telio.State.Disconnected],
                            wait_for_repeating_event=True,
                        ),
                        60,
                    ),
                )

                async with Ping(alpha_connection, CLIENT_BETA_IP) as ping:
                    await testing.wait_defined(ping.wait_for_next_ping(), 60)

        await asyncio.gather(
            testing.wait_defined(
                alpha_client.wait_for_any_derp_state([telio.State.Connected]), 60
            ),
            testing.wait_defined(
                beta_client.wait_for_any_derp_state([telio.State.Connected]), 60
            ),
        )

        # wait for first direct connections between peers
        await asyncio.gather(
            testing.wait_lengthy(
                alpha_client.handshake(
                    beta.public_key,
                    telio.PathType.Direct,
                )
            ),
            testing.wait_lengthy(
                beta_client.handshake(
                    alpha.public_key,
                    telio.PathType.Direct,
                )
            ),
        )

        # make sure direct connection is true by breaking derp connections
        await _check_if_true_direct_connection()

        # wait for derp connection to be restored
        await asyncio.gather(
            testing.wait_defined(
                alpha_client.wait_for_any_derp_state(
                    [telio.State.Connected], wait_for_repeating_event=True
                ),
                60,
            ),
            testing.wait_defined(
                beta_client.wait_for_any_derp_state(
                    [telio.State.Connected], wait_for_repeating_event=True
                ),
                60,
            ),
        )

        alpha_gw_connection = await exit_stack.enter_async_context(
            new_connection_raw(ConnectionTag.DOCKER_UPNP_GW_1)
        )
        beta_gw_connection = await exit_stack.enter_async_context(
            new_connection_raw(ConnectionTag.DOCKER_UPNP_GW_2)
        )

        # break upnp connection and wait for relay handshake
        async with AsyncExitStack() as temp_exit_stack:
            await temp_exit_stack.enter_async_context(
                new_router(alpha_gw_connection).restart_upnpd()
            )
            await temp_exit_stack.enter_async_context(
                new_router(beta_gw_connection).restart_upnpd()
            )

            await alpha_gw_connection.create_process(
                ["conntrack", "-D", "-p", "udp"]
            ).execute()
            await beta_gw_connection.create_process(
                ["conntrack", "-D", "-p", "udp"]
            ).execute()

            # this needs to be done, cuz killing upnpd removes rule from iptables
            await beta_gw_connection.create_process(
                ["/opt/bin/configure-port-restricted-cone-nat"]
            ).execute()
            await alpha_gw_connection.create_process(
                ["/opt/bin/configure-port-restricted-cone-nat"]
            ).execute()

            await asyncio.gather(
                testing.wait_defined(
                    alpha_client.handshake(
                        beta.public_key,
                        telio.PathType.Relay,
                        wait_for_repeating_event=True,
                    ),
                    60,
                ),
                testing.wait_defined(
                    beta_client.handshake(
                        alpha.public_key,
                        telio.PathType.Relay,
                        wait_for_repeating_event=True,
                    ),
                    60,
                ),
            )

            async with Ping(alpha_connection, CLIENT_BETA_IP) as ping:
                await testing.wait_defined(ping.wait_for_next_ping(), 60)

        # restore upnp and wait for direct connection to be restored
        await asyncio.gather(
            testing.wait_defined(
                alpha_client.handshake(
                    beta.public_key,
                    telio.PathType.Direct,
                    wait_for_repeating_event=True,
                ),
                60,
            ),
            testing.wait_defined(
                beta_client.handshake(
                    alpha.public_key,
                    telio.PathType.Direct,
                    wait_for_repeating_event=True,
                ),
                60,
            ),
        )

        # make sure direct connection is true by breaking derp connections
        await _check_if_true_direct_connection()
