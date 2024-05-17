import config
import pytest
from utils import stun
from utils.connection_util import ConnectionTag, new_connection_by_tag


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "connection_tag,public_ip",
    [
        pytest.param(ConnectionTag.DOCKER_CONE_CLIENT_1, "10.0.254.1"),
        pytest.param(
            ConnectionTag.WINDOWS_VM_1,
            "10.0.254.7",
            marks=pytest.mark.windows,
        ),
        pytest.param(ConnectionTag.MAC_VM, "10.0.254.7", marks=pytest.mark.mac),
    ],
)
async def test_client_basic_stun(connection_tag: ConnectionTag, public_ip: str) -> None:
    async with new_connection_by_tag(connection_tag) as connection:
        ip = await stun.get(connection, config.STUN_SERVER)
        assert ip == public_ip, f"wrong public ip for the client {ip}"
