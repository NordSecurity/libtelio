import telio
import pytest
import asyncio

from contextlib import AsyncExitStack
from utils import ConnectionTag, new_connection_by_tag, testing
from derp_cli import check_derp_connection
from mesh_api import API
from config import DERP_PRIMARY
from typing import Optional


async def check_fake_derp_connection(client: telio.Client) -> Optional[telio.Client]:
    while True:
        await client.fake_derp_events()
        output = reversed(client._process.get_stdout().splitlines())

        for line in output:
            if "- Server {" in line:
                if f"Connected," in line:
                    return client
                else:
                    break

        await asyncio.sleep(0.1)


@pytest.mark.asyncio
@pytest.mark.skip(reason="the test is flaky - JIRA issue: LLT-3078")
async def test_verify_pk_on_packets() -> None:
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
            )
        )

        beta_client = await exit_stack.enter_async_context(
            telio.run_meshnet(
                beta_connection,
                beta,
                api.get_meshmap(beta.id),
                telio.AdapterType.BoringTun,
            )
        )
        await testing.wait_lengthy(check_derp_connection(alpha_client, DERP_IP, True))
        await testing.wait_lengthy(check_derp_connection(beta_client, DERP_IP, True))

        await testing.wait_long(
            alpha_client.create_fake_derprelay_to_derp01(
                "WMsz2uwtYIlqDEfkGjLX7tz1hcK+ylecHvL+z0tAqWM=",
                "xrlurQkz0Js0L4CSMQMbkBZdpUjEkrEd1Vxbo+a3yHg=",
            )
        )
        await testing.wait_long(
            beta_client.create_fake_derprelay_to_derp01(
                "MJvSFfXMiXOk6gI/WzabBSul3IsgNMfAKseaMT4AN0k=",
                "sT82kS+0VFH6TPIlLqFzOJ7e4OOc8udFCZt1O9ZUv3k=",
            )
        )

        await testing.wait_short(check_fake_derp_connection(alpha_client))
        await testing.wait_short(check_fake_derp_connection(beta_client))

        # Send and receive Byte on FakeDerp
        await alpha_client.send_message_from_fake_derp_relay(
            "xrlurQkz0Js0L4CSMQMbkBZdpUjEkrEd1Vxbo+a3yHg=",
            ["0", "0", "2", "3", "5", "6"],
        )
        await beta_client.recv_message_from_fake_derp_relay()

        assert "bytes: [0, 0, 2, 3, 5, 6]" in beta_client._process.get_stdout()

        # Remove Alpha pk from Beta allowed list
        await testing.wait_long(beta_client.disconnect_fake_derprelay())
        await testing.wait_long(
            beta_client.create_fake_derprelay_to_derp01(
                "MJvSFfXMiXOk6gI/WzabBSul3IsgNMfAKseaMT4AN0k=",
                # Dummy public key
                "41CCEssnYIh8/8D8YvbTfWEcFanG3D0I0z1tRcN1Lyc=",
            )
        )
        await testing.wait_normal(check_fake_derp_connection(beta_client))

        # Beta should not recveive this message
        await alpha_client.send_message_from_fake_derp_relay(
            "xrlurQkz0Js0L4CSMQMbkBZdpUjEkrEd1Vxbo+a3yHg=",
            ["0", "0", "0", "1", "1", "1"],
        )
        await beta_client.recv_message_from_fake_derp_relay()
        assert "bytes: [0, 0, 0, 1, 1, 1]" not in beta_client._process.get_stdout()
