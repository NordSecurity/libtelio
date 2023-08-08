import asyncio
import pytest
from contextlib import AsyncExitStack
from utils.connection_util import ConnectionTag, new_connection_by_tag

TESTING_STRING = "test failed"
LOCAL_PORT = 1235
LOCAL_IP = "10.0.254.4"


@pytest.mark.nat
@pytest.mark.asyncio
async def test_fullcone_nat() -> None:
    async with AsyncExitStack() as exit_stack:
        connection_1 = await exit_stack.enter_async_context(
            new_connection_by_tag(ConnectionTag.DOCKER_FULLCONE_CLIENT_1)
        )

        connection_2 = await exit_stack.enter_async_context(
            new_connection_by_tag(ConnectionTag.DOCKER_CONE_CLIENT_1)
        )

        event = asyncio.Event()

        async def on_stdout(stdout: str) -> None:
            print(stdout)
            if TESTING_STRING in stdout:
                event.set()

        # listen for udp packets on connection1 local port
        listening_process = await exit_stack.enter_async_context(
            connection_1.create_process(
                ["nc", "-n", "-l", "-u", "-v", "-p", str(LOCAL_PORT)]
            ).run(stdout_callback=on_stdout)
        )

        await listening_process.wait_stdin_ready()

        # send udp packet from connection2 to connection1 to its external ip
        send_process = await exit_stack.enter_async_context(
            connection_2.create_process(
                ["nc", "-n", "-u", "-v", LOCAL_IP, str(LOCAL_PORT)]
            ).run()
        )
        await send_process.wait_stdin_ready()
        await asyncio.sleep(1)
        await send_process.write_stdin(TESTING_STRING)

        await asyncio.sleep(2)

        assert len(listening_process.get_stdout()) == 0
