from utils.asyncio_util import run_async_context
from utils import ConnectionTag, new_connection_by_tag, connection_util
import asyncio
import pytest
import re
import utils.testing as testing


@pytest.mark.nat
@pytest.mark.asyncio
@pytest.mark.parametrize(
    "connection_tag,nat_string",
    [
        pytest.param(
            ConnectionTag.DOCKER_CONE_CLIENT_1,
            "PortRestrictedCone",
        ),
        pytest.param(
            ConnectionTag.DOCKER_FULLCONE_CLIENT_1,
            "FullCone",
        ),
        pytest.param(
            ConnectionTag.DOCKER_SYMMETRIC_CLIENT_1,
            "Symmetric",
        ),
    ],
)
async def test_nat_type(connection_tag, nat_string) -> None:
    async with new_connection_by_tag(connection_tag) as connection:
        tcli_path = connection_util.get_libtelio_binary_path("tcli", connection)
        process = connection.create_process([tcli_path])

        event = asyncio.Event()

        async def print_result(stdout: str) -> None:
            if "Nat Type:" in stdout:
                event.set()

        async with run_async_context(process.execute(stdout_callback=print_result)):
            await process.wait_stdin_ready()
            await process.write_stdin("nat address  10.0.1.1:3478\n")
            await testing.wait_lengthy(event.wait())
            result = re.search(r"Nat Type: (.*)", process.get_stdout())
            assert result
            assert result.group(1) == nat_string
