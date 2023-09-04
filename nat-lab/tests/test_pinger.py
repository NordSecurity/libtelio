import asyncio
import enum
import pytest
import socket
import struct
import telio
from contextlib import AsyncExitStack
from mesh_api import API
from protobuf.pinger_pb2 import Pinger
from telio import AdapterType
from utils import testing
from utils.asyncio_util import run_async_context
from utils.connection_util import ConnectionTag, new_connection_by_tag, LAN_ADDR_MAP


class PingType(enum.Enum):
    PING = 0
    PONG = 1
    MALFORMED = 2


async def send_ping_pong(connection_tag: ConnectionTag, ping_type: PingType) -> None:
    ping = Pinger()
    ping.message_type = ping.PING  # pylint: disable=no-member
    ping.session = 3
    ping.start_timestamp = 10

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    await asyncio.sleep(0.1)

    # Send a PING type message
    if ping_type == PingType.PING:
        sock.sendto(
            struct.pack(">BBB", 7, 0, 3) + ping.SerializeToString(),
            (LAN_ADDR_MAP[connection_tag], 5000),
        )
    elif ping_type == PingType.PONG:
        # Send a PONG type message
        ping.message_type = ping.PONG  # pylint: disable=no-member
        sock.sendto(
            struct.pack(">BBB", 9, 0, 3) + ping.SerializeToString(),
            (LAN_ADDR_MAP[connection_tag], 5000),
        )
    else:
        sock.sendto(
            struct.pack(">BBBBBBBBBBBB", 4, 0, 8, 17, 9, 0, 0, 0, 0, 0, 0, 0),
            (LAN_ADDR_MAP[connection_tag], 5000),
        )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "connection_tag,adapter_type",
    [
        pytest.param(
            ConnectionTag.DOCKER_CONE_CLIENT_1,
            AdapterType.BoringTun,
        ),
        pytest.param(
            ConnectionTag.DOCKER_CONE_CLIENT_1,
            AdapterType.LinuxNativeWg,
            marks=pytest.mark.linux_native,
        ),
        pytest.param(
            ConnectionTag.WINDOWS_VM,
            AdapterType.WindowsNativeWg,
            marks=pytest.mark.windows,
        ),
        pytest.param(
            ConnectionTag.WINDOWS_VM,
            AdapterType.WireguardGo,
            marks=pytest.mark.windows,
        ),
        pytest.param(
            ConnectionTag.MAC_VM,
            AdapterType.BoringTun,
            marks=pytest.mark.mac,
        ),
    ],
)
async def test_ping_pong(
    connection_tag: ConnectionTag,
    adapter_type: AdapterType,
) -> None:
    async with AsyncExitStack() as exit_stack:
        api = API()

        alpha = api.default_config_one_node()

        connection_alpha = await exit_stack.enter_async_context(
            new_connection_by_tag(connection_tag)
        )

        client_alpha = await exit_stack.enter_async_context(
            telio.Client(connection_alpha, alpha, adapter_type).run_meshnet(
                api.get_meshmap(alpha.id)
            )
        )

        pinger_event = client_alpha.wait_for_output("Pinger")
        ponger_event = client_alpha.wait_for_output("Ponger")

        # Send PING type message
        await exit_stack.enter_async_context(
            run_async_context(testing.wait_lengthy(client_alpha.receive_ping()))
        )
        await testing.wait_lengthy(send_ping_pong(connection_tag, PingType.PING))

        # Send PONG type message
        await exit_stack.enter_async_context(
            run_async_context(testing.wait_lengthy(client_alpha.receive_ping()))
        )
        await testing.wait_lengthy(send_ping_pong(connection_tag, PingType.PONG))

        await testing.wait_long(pinger_event.wait())
        await testing.wait_long(ponger_event.wait())


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "connection_tag,adapter_type",
    [
        pytest.param(
            ConnectionTag.DOCKER_CONE_CLIENT_1,
            AdapterType.BoringTun,
        ),
        pytest.param(
            ConnectionTag.DOCKER_CONE_CLIENT_1,
            AdapterType.LinuxNativeWg,
            marks=pytest.mark.linux_native,
        ),
        pytest.param(
            ConnectionTag.WINDOWS_VM,
            AdapterType.WindowsNativeWg,
            marks=pytest.mark.windows,
        ),
        pytest.param(
            ConnectionTag.WINDOWS_VM,
            AdapterType.WireguardGo,
            marks=pytest.mark.windows,
        ),
        pytest.param(
            ConnectionTag.MAC_VM,
            AdapterType.BoringTun,
            marks=pytest.mark.mac,
        ),
    ],
)
async def test_send_malform_pinger_packet(
    connection_tag: ConnectionTag,
    adapter_type: AdapterType,
) -> None:
    async with AsyncExitStack() as exit_stack:
        api = API()

        alpha = api.default_config_one_node()

        connection_alpha = await exit_stack.enter_async_context(
            new_connection_by_tag(connection_tag)
        )

        client_alpha = await exit_stack.enter_async_context(
            telio.Client(connection_alpha, alpha, adapter_type).run_meshnet(
                api.get_meshmap(alpha.id)
            )
        )

        unexpected_packet_event = client_alpha.wait_for_output("Unexpected packet: ")

        # Send malformed PingerMsg
        await exit_stack.enter_async_context(
            run_async_context(testing.wait_lengthy(client_alpha.receive_ping()))
        )
        await testing.wait_lengthy(send_ping_pong(connection_tag, PingType.MALFORMED))

        await testing.wait_long(unexpected_packet_event.wait())
