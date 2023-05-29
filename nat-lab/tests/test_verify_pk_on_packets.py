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
            private_key="mODRJKABR4wDCjXn899QO6wb83azXKZF7hcfX8dWuUA=",
            public_key="3XCOtCGl5tZJ8N5LksxkjfeqocW0BH2qmARD7qzHDkI=",
        )
        beta = api.register(
            name="beta",
            id="7b4548ca-fe5a-4597-8513-896f38c6d6ae",
            private_key="GN+D2Iy9p3UmyBZhgxU4AhbLT6sxY0SUhXu0a0TuiV4=",
            public_key="UnB+btGMEBXcR7EchMi28Hqk0Q142WokO6n313dt3mc=",
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
                "YM/cgTcnTGeGqnDVSD19sWHKr3yOn45JJ5ngQ/9InFQ=",
                "TNRZu9dcu7xM3b1jiVlVAVCf5zcyT0B98q7zgKOGEQI=",
            )
        )
        await testing.wait_long(
            beta_client.create_fake_derprelay_to_derp01(
                "4NuMvvYQ9bpUE8nokwCjbZiOCeb1iqVKfpDsHkmDXXM=",
                "BXhQTS33twKHzYh2hnWSiuX2s+8jejdBKbSpkRyVwV4=",
            )
        )

        await testing.wait_short(check_fake_derp_connection(alpha_client))
        await testing.wait_short(check_fake_derp_connection(beta_client))

        # Send and receive Byte on FakeDerp
        await alpha_client.send_message_from_fake_derp_relay(
            "TNRZu9dcu7xM3b1jiVlVAVCf5zcyT0B98q7zgKOGEQI=",
            ["0", "0", "2", "3", "5", "6"],
        )
        await beta_client.recv_message_from_fake_derp_relay()

        assert "bytes: [0, 0, 2, 3, 5, 6]" in beta_client._process.get_stdout()

        # Remove Alpha pk from Beta allowed list
        await testing.wait_long(beta_client.disconnect_fake_derprelay())
        await testing.wait_long(
            beta_client.create_fake_derprelay_to_derp01(
                "4NuMvvYQ9bpUE8nokwCjbZiOCeb1iqVKfpDsHkmDXXM=",
                # Dummy public key
                "3XCOtCGl5tZJ8N5LksxkjfeqocW0BH2qmARD7qzHDkI=",
            )
        )
        await testing.wait_normal(check_fake_derp_connection(beta_client))

        # Beta should not recveive this message
        await alpha_client.send_message_from_fake_derp_relay(
            "TNRZu9dcu7xM3b1jiVlVAVCf5zcyT0B98q7zgKOGEQI=",
            ["0", "0", "0", "1", "1", "1"],
        )
        await beta_client.recv_message_from_fake_derp_relay()
        assert "bytes: [0, 0, 0, 1, 1, 1]" not in beta_client._process.get_stdout()
