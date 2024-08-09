import pytest
from contextlib import AsyncExitStack
from helpers import SetupParameters, setup_environment
from uniffi.telio_bindings import NatType
from utils.connection_util import ConnectionTag


@pytest.mark.nat
@pytest.mark.asyncio
@pytest.mark.parametrize(
    "connection_tag,nat_type",
    [
        pytest.param(ConnectionTag.DOCKER_CONE_CLIENT_1, NatType.PORT_RESTRICTED_CONE),
        pytest.param(ConnectionTag.DOCKER_FULLCONE_CLIENT_1, NatType.FULL_CONE),
        pytest.param(ConnectionTag.DOCKER_SYMMETRIC_CLIENT_1, NatType.SYMMETRIC),
    ],
)
async def test_nat_type(connection_tag: ConnectionTag, nat_type: NatType) -> None:
    async with AsyncExitStack() as exit_stack:
        env = await exit_stack.enter_async_context(
            setup_environment(
                exit_stack, [SetupParameters(connection_tag=connection_tag)]
            )
        )
        client, *_ = env.clients
        assert (await client.get_nat("10.0.1.1", 3478)) == nat_type
