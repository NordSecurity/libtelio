import asyncio
import platform
import pytest
import telio
from contextlib import AsyncExitStack
from mesh_api import API
from typing import Optional
from utils.connection_util import ConnectionTag, new_connection_by_tag

if platform.machine() != "x86_64":
    import pure_wg as Key
else:
    from python_wireguard import Key  # type: ignore


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
@pytest.mark.skip(reason="test doesnt work at all - JIRA issue: LLT-3078")
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
            telio.Client(alpha_connection, alpha, telio.AdapterType.BoringTun).run(
                api.get_meshmap(alpha.id)
            )
        )

        beta_client = await exit_stack.enter_async_context(
            telio.Client(beta_connection, beta, telio.AdapterType.BoringTun).run(
                api.get_meshmap(beta.id)
            )
        )
        await asyncio.gather(
            alpha_client.wait_for_state_on_any_derp([telio.State.Connected]),
            beta_client.wait_for_state_on_any_derp([telio.State.Connected]),
        )

        sk_for_alpha, pk_for_alpha = Key.key_pair()
        sk_for_beta, pk_for_beta = Key.key_pair()

        await asyncio.gather(
            alpha_client.create_fake_derprelay_to_derp01(
                sk_for_alpha,
                pk_for_alpha,
            ),
            beta_client.create_fake_derprelay_to_derp01(
                sk_for_beta,
                pk_for_beta,
            ),
        )

        await asyncio.gather(
            check_fake_derp_connection(alpha_client),
            check_fake_derp_connection(beta_client),
        )

        # Send and receive Byte on FakeDerp
        await alpha_client.send_message_from_fake_derp_relay(
            pk_for_alpha,
            ["0", "0", "2", "3", "5", "6"],
        )
        await beta_client.recv_message_from_fake_derp_relay()

        assert "bytes: [0, 0, 2, 3, 5, 6]" in beta_client.get_stdout()

        # Remove Alpha pk from Beta allowed list
        await beta_client.disconnect_fake_derprelay()
        pk_dummy = Key.key_pair()[1]
        await beta_client.create_fake_derprelay_to_derp01(
            pk_dummy,
            beta.public_key,
        )
        await check_fake_derp_connection(beta_client)

        # Beta should not recveive this message
        await alpha_client.send_message_from_fake_derp_relay(
            pk_for_alpha,
            ["0", "0", "0", "1", "1", "1"],
        )
        await beta_client.recv_message_from_fake_derp_relay()
        assert "bytes: [0, 0, 0, 1, 1, 1]" not in beta_client.get_stdout()
