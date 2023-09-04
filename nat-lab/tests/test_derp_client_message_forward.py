import pytest
from contextlib import AsyncExitStack
from derp_cli import DerpClient, DerpTarget
from utils import testing
from utils.connection_util import ConnectionTag, new_connection_by_tag

DERP_SERVER = "http://10.0.10.1:8765"
DERP_SERVER_2 = "http://10.0.10.2:8765"
TESTING_STRING = "testing"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "connection_tag",
    [
        pytest.param(
            ConnectionTag.DOCKER_CONE_CLIENT_1,
        ),
        pytest.param(
            ConnectionTag.WINDOWS_VM,
            marks=pytest.mark.windows,
        ),
    ],
)
async def test_derp_client_message_forward(connection_tag: ConnectionTag) -> None:
    async with AsyncExitStack() as exit_stack:
        connection_1 = await exit_stack.enter_async_context(
            new_connection_by_tag(connection_tag)
        )
        connection_2 = await exit_stack.enter_async_context(
            new_connection_by_tag(ConnectionTag.DOCKER_CONE_CLIENT_2)
        )

        # Test message relay with identical DERP servers
        async with DerpTarget(connection_1, DERP_SERVER).run() as target:
            async with DerpClient(connection_2, DERP_SERVER, TESTING_STRING).run():
                await testing.wait_lengthy(target.wait_message_received(TESTING_STRING))

        # Test message relay with different DERP servers
        async with DerpTarget(connection_1, DERP_SERVER).run() as target:
            async with DerpClient(connection_2, DERP_SERVER_2, TESTING_STRING).run():
                await testing.wait_lengthy(target.wait_message_received(TESTING_STRING))
