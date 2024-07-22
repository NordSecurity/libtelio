import pytest
from contextlib import AsyncExitStack
from derp_cli import DerpClient, DerpTarget, save_derpcli_logs
from helpers import setup_connections
from mesh_api import start_tcpdump, stop_tcpdump
from utils.asyncio_util import run_async_context
from utils.connection import DockerConnection
from utils.connection_util import ConnectionTag

DERP_SERVER = "http://10.0.10.1:8765"
DERP_SERVER_2 = "http://10.0.10.2:8765"
TESTING_STRING = "testing"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "connection_tag",
    [
        ConnectionTag.DOCKER_CONE_CLIENT_1,
        pytest.param(ConnectionTag.WINDOWS_VM_1, marks=[pytest.mark.windows]),
    ],
)
async def test_derp_client_message_forward(connection_tag: ConnectionTag) -> None:
    async with AsyncExitStack() as exit_stack:
        connection_1, connection_2 = [
            conn.connection
            for conn in await setup_connections(
                exit_stack, [connection_tag, ConnectionTag.DOCKER_CONE_CLIENT_2]
            )
        ]
        if isinstance(connection_1, DockerConnection) and isinstance(
            connection_2, DockerConnection
        ):
            start_tcpdump(connection_1.container_name())
            start_tcpdump(connection_2.container_name())
            # Test message relay with identical DERP servers
            async with DerpTarget(connection_1, DERP_SERVER).run() as target:
                async with run_async_context(
                    target.wait_message_received(TESTING_STRING)
                ) as event:
                    async with DerpClient(
                        connection_2, DERP_SERVER, TESTING_STRING
                    ).run():
                        await event
                await save_derpcli_logs(connection_1, log_name="identical")
                await save_derpcli_logs(connection_2, log_name="identical")

            # Test message relay with different DERP servers
            async with DerpTarget(connection_1, DERP_SERVER).run() as target:
                async with run_async_context(
                    target.wait_message_received(TESTING_STRING)
                ) as event:
                    async with DerpClient(
                        connection_2, DERP_SERVER_2, TESTING_STRING
                    ).run():
                        await event
                await save_derpcli_logs(connection_1, log_name="different")
                await save_derpcli_logs(connection_2, log_name="different")
            stop_tcpdump([connection_2.container_name()])
            stop_tcpdump([connection_1.container_name()])
