from config import (
    DERP_PRIMARY,
    DOCKER_CONE_CLIENT_1_LAN_ADDR,
    DOCKER_CONE_CLIENT_2_LAN_ADDR,
)
from contextlib import AsyncExitStack
from mesh_api import API
from utils import ConnectionTag, new_connection_by_tag, testing
from derp_cli import check_derp_connection
from telio import PathType
import asyncio
import pytest
import telio


@pytest.mark.asyncio
@pytest.mark.skip(reason="depends on println! statements in telio-route")
async def test_cmm_responder() -> None:
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

        beta.set_peer_firewall_settings(alpha.id, allow_incoming_connections=True)
        alpha.set_peer_firewall_settings(beta.id, allow_incoming_connections=True)

        alpha_connection = await exit_stack.enter_async_context(
            new_connection_by_tag(ConnectionTag.DOCKER_CONE_CLIENT_1)
        )

        beta_connection = await exit_stack.enter_async_context(
            new_connection_by_tag(ConnectionTag.DOCKER_CONE_CLIENT_2)
        )

        alpha_client = await exit_stack.enter_async_context(
            telio.run_meshnet(
                alpha_connection,
                alpha,
                api.get_meshmap(alpha.id),
                telio.AdapterType.BoringTun,
                PathType.Direct,
            )
        )

        beta_client = await exit_stack.enter_async_context(
            telio.run_meshnet(
                beta_connection,
                beta,
                api.get_meshmap(beta.id),
                telio.AdapterType.BoringTun,
                PathType.Direct,
            )
        )

        await asyncio.sleep(50)

        await testing.wait_lengthy(check_derp_connection(alpha_client, DERP_IP, True))
        await testing.wait_lengthy(check_derp_connection(beta_client, DERP_IP, True))

        assert beta.public_key in await alpha_client.get_sent_cmm_responses()
        assert alpha.public_key in await beta_client.get_sent_cmm_responses()

        assert (
            DOCKER_CONE_CLIENT_2_LAN_ADDR in await alpha_client.get_pinged_endpoints()
        )
        assert DOCKER_CONE_CLIENT_1_LAN_ADDR in await beta_client.get_pinged_endpoints()
