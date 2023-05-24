import asyncio
from contextlib import AsyncExitStack

from utils import Ping
from config import DERP_PRIMARY, DERP_SECONDARY, DERP_TERTIARY
import config
import pytest
import telio
import time
from typing import Optional
import re
import utils.testing as testing
from mesh_api import API, DERP_SERVERS
from telio import AdapterType
from telio_features import TelioFeatures, Direct
from utils import ConnectionTag, new_connection_by_tag
from utils.asyncio_util import run_async_context

ALPHA_NODE_ADDRESS = "100.64.0.4"
DNS_SERVER_ADDRESS = config.LIBTELIO_DNS_IP
CONE_CLIENT_IP_ADDRESS = "192.168.101.104"
TESTING_STRING = "seniukai, skyle pramusta"
TESTING_STRING_BACK = "sending message back"
UPNP_PROVIDER = ["upnp"]


async def check_derp_connection(
    client: telio.Client, server_ip: str, state: bool
) -> Optional[telio.DerpServer]:
    while True:
        server = await client.get_derp_server()

        if isinstance(server, telio.DerpServer):
            if state:
                if server.ipv4 == server_ip and server.conn_state == "connected":
                    return server
            else:
                if server.ipv4 != server_ip:
                    return server
        await asyncio.sleep(0.1)


@pytest.mark.asyncio
async def test_direct_upnp_connection() -> None:
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
                telio_features=TelioFeatures(direct=Direct(providers=UPNP_PROVIDER)),
            )
        )

        beta_client = await exit_stack.enter_async_context(
            telio.run_meshnet(
                beta_connection,
                beta,
                api.get_meshmap(beta.id),
                telio.AdapterType.BoringTun,
                telio_features=TelioFeatures(direct=Direct(providers=UPNP_PROVIDER)),
            )
        )

        await testing.wait_lengthy(check_derp_connection(alpha_client, DERP_IP, True))
        await testing.wait_lengthy(check_derp_connection(beta_client, DERP_IP, True))

        await testing.wait_lengthy(
            alpha_client._events.wait_for_state(
                "Q1M3VKUcfTmGsrRzY6BpNds1yDIUvPVcs/2TySv/t1U=",
                telio.State.Connected,
                telio.PathType.Direct,
            )
        )
        await testing.wait_lengthy(
            beta_client._events.wait_for_state(
                "41CCEssnYIh8/8D8YvbTfWEcFanG3D0I0z1tRcN1Lyc=",
                telio.State.Connected,
                telio.PathType.Direct,
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
            await testing.wait_defined(ping.wait_for_next_ping(), 40)
