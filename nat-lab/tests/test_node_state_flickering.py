from mesh_api import API
import pytest
import telio
import utils.testing as testing
from contextlib import AsyncExitStack
from utils import ConnectionTag, new_connection_by_tag
import asyncio


@pytest.mark.asyncio
@pytest.mark.timeout(3 * 60 + 60)
@pytest.mark.long
async def test_node_state_flickering() -> None:
    async with AsyncExitStack() as exit_stack:
        api = API()

        alpha = api.register(
            name="alpha",
            id="96ddb926-4b86-11ec-81d3-0242ac130003",
            private_key="JcnzdKlaRd56T/EnHkbVpNCvYo64YLDpRZsJq14ZU1A=",
            public_key="eES5D8OiQyMXf/pG0ibJSD2QhSnKLW0+6jW7mvtfL0g=",
        )

        beta = api.register(
            name="beta",
            id="7b4548ca-fe5a-4597-8513-896f38c6d6ae",
            private_key="+KqbDiS4KkWlB1iI9DfAnQTX7+c4YvFQzlLQWljbVHc=",
            public_key="5eURKcx0OlMyz2kXOibfHklUwF9pgplc0eBdlo4B3gk=",
        )

        api.assign_ip(alpha.id, "100.64.0.11")
        api.assign_ip(beta.id, "100.64.0.22")

        connection_alpha = await exit_stack.enter_async_context(
            new_connection_by_tag(ConnectionTag.DOCKER_CONE_CLIENT_1)
        )

        client_alpha = await exit_stack.enter_async_context(
            telio.run_meshnet(
                connection_alpha,
                alpha,
                api.get_meshmap(alpha.id),
            )
        )

        client_beta = await exit_stack.enter_async_context(
            telio.run_meshnet(
                await exit_stack.enter_async_context(
                    new_connection_by_tag(ConnectionTag.DOCKER_CONE_CLIENT_2)
                ),
                beta,
                api.get_meshmap(beta.id),
            )
        )

        await testing.wait_long(client_alpha.handshake(beta.public_key))
        await testing.wait_long(client_beta.handshake(alpha.public_key))

        with pytest.raises(asyncio.TimeoutError):
            await asyncio.wait_for(
                client_alpha.wait_for_any_node_event(beta.public_key), 3 * 60
            )
