import pytest
import utils.testing as testing
from utils import ConnectionTag, new_connection_by_tag
from contextlib import AsyncExitStack
from utils.asyncio_util import run_async_context
import asyncio

TESTING_STRING = "seniukai, skyle pramusta"


@pytest.mark.asyncio
async def test_hole_punch() -> None:
    async with AsyncExitStack() as exit_stack:
        connection_1 = await exit_stack.enter_async_context(
            new_connection_by_tag(ConnectionTag.DOCKER_UPNP_CLIENT_1)
        )

        connection_2 = await exit_stack.enter_async_context(
            new_connection_by_tag(ConnectionTag.DOCKER_CONE_CLIENT_1)
        )

        # create port mapping rule
        PUBLIC_IP = "10.0.254.5"
        LOCAL_PORT = 1000
        PUBLIC_PORT = 1001
        process = connection_1.create_process(
            [
                "upnpc",
                "-i",
                "-a",
                "192.168.105.88",
                str(LOCAL_PORT),
                str(PUBLIC_PORT),
                "udp",
            ]
        )
        await testing.wait_long(process.execute())

        assert (
            f"external {PUBLIC_IP}:1001 UDP is redirected to internal 192.168.105.88:1000 (duration=0)"
            in process.get_stdout()
        )

        # listen for udp packets on connection1 local port
        event = asyncio.Event()
        listening_process = connection_1.create_process(
            ["nc", "-n", "-l", "-u", "-v", "-p", str(LOCAL_PORT)]
        )

        async def on_stdout(stdout: str) -> None:
            print(stdout)
            if TESTING_STRING in stdout:
                event.set()

        await exit_stack.enter_async_context(
            run_async_context(listening_process.execute(stdout_callback=on_stdout))
        )
        await listening_process.wait_stdin_ready()

        # send udp packet from connection2 to connection1 to its external ip
        send_process = connection_2.create_process(
            ["nc", "-n", "-u", "-v", PUBLIC_IP, str(PUBLIC_PORT)]
        )

        await exit_stack.enter_async_context(run_async_context(send_process.execute()))
        await send_process.wait_stdin_ready()
        await asyncio.sleep(1)
        await send_process.write_stdin(TESTING_STRING + "\n")

        await testing.wait_defined(event.wait(), 60)
