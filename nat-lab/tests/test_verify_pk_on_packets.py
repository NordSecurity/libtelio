import asyncio
import pytest
import telio
from contextlib import AsyncExitStack
from mesh_api import API
from typing import Optional
from utils import testing
from utils.connection_util import ConnectionTag, new_connection_by_tag


async def check_fake_derp_connection(client: telio.Client) -> Optional[telio.Client]:
    while True:
        await client.fake_derp_events()
        output = reversed(client.get_stdout().splitlines())

        for line in output:
            if "- Server {" in line:
                if "Connected," in line:
                    return client
                break

        await asyncio.sleep(0.1)


@pytest.mark.asyncio
@pytest.mark.xfail(reason="the test is flaky - JIRA issue: LLT-3078")
async def test_verify_pk_on_packets() -> None:
    async with AsyncExitStack() as exit_stack:
        api = API()
        (alpha, beta) = api.default_config_two_nodes()

        alpha_connection = await exit_stack.enter_async_context(
            new_connection_by_tag(ConnectionTag.DOCKER_CONE_CLIENT_1)
        )

        beta_connection = await exit_stack.enter_async_context(
            new_connection_by_tag(ConnectionTag.DOCKER_CONE_CLIENT_2)
        )

        alpha_client = await exit_stack.enter_async_context(
            telio.Client(
                alpha_connection, alpha, telio.AdapterType.BoringTun
            ).run_meshnet(api.get_meshmap(alpha.id))
        )

        beta_client = await exit_stack.enter_async_context(
            telio.Client(
                beta_connection, beta, telio.AdapterType.BoringTun
            ).run_meshnet(api.get_meshmap(beta.id))
        )
        await testing.wait_lengthy(
            asyncio.gather(
                alpha_client.wait_for_state_on_any_derp([telio.State.Connected]),
                beta_client.wait_for_state_on_any_derp([telio.State.Connected]),
            )
        )

        await testing.wait_long(
            asyncio.gather(
                alpha_client.create_fake_derprelay_to_derp01(
                    "YM/cgTcnTGeGqnDVSD19sWHKr3yOn45JJ5ngQ/9InFQ=",
                    "TNRZu9dcu7xM3b1jiVlVAVCf5zcyT0B98q7zgKOGEQI=",
                ),
                beta_client.create_fake_derprelay_to_derp01(
                    "4NuMvvYQ9bpUE8nokwCjbZiOCeb1iqVKfpDsHkmDXXM=",
                    "BXhQTS33twKHzYh2hnWSiuX2s+8jejdBKbSpkRyVwV4=",
                ),
            )
        )

        await testing.wait_long(
            asyncio.gather(
                check_fake_derp_connection(alpha_client),
                check_fake_derp_connection(beta_client),
            )
        )

        # Send and receive Byte on FakeDerp
        await testing.wait_normal(
            alpha_client.send_message_from_fake_derp_relay(
                "TNRZu9dcu7xM3b1jiVlVAVCf5zcyT0B98q7zgKOGEQI=",
                ["0", "0", "2", "3", "5", "6"],
            )
        )
        await testing.wait_normal(beta_client.recv_message_from_fake_derp_relay())

        assert "bytes: [0, 0, 2, 3, 5, 6]" in beta_client.get_stdout()

        # Remove Alpha pk from Beta allowed list
        await testing.wait_long(beta_client.disconnect_fake_derprelay())
        await testing.wait_long(
            beta_client.create_fake_derprelay_to_derp01(
                "4NuMvvYQ9bpUE8nokwCjbZiOCeb1iqVKfpDsHkmDXXM=",
                # Dummy public key
                beta.public_key,
            )
        )
        await testing.wait_normal(check_fake_derp_connection(beta_client))

        # Beta should not recveive this message
        await testing.wait_normal(
            alpha_client.send_message_from_fake_derp_relay(
                "TNRZu9dcu7xM3b1jiVlVAVCf5zcyT0B98q7zgKOGEQI=",
                ["0", "0", "0", "1", "1", "1"],
            )
        )
        await testing.wait_normal(beta_client.recv_message_from_fake_derp_relay())
        assert "bytes: [0, 0, 0, 1, 1, 1]" not in beta_client.get_stdout()
