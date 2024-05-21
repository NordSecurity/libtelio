import asyncio
import enum
import pytest
import socket
import struct
from contextlib import AsyncExitStack
from helpers import SetupParameters, setup_mesh_nodes
from protobuf.pinger_pb2 import Pinger
from utils.asyncio_util import run_async_context
from utils.connection_util import ConnectionTag, LAN_ADDR_MAP


class PingType(enum.Enum):
    PING = 0
    PONG = 1
    MALFORMED = 2


async def send_ping_pong(ping_type) -> None:
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
            (LAN_ADDR_MAP[ConnectionTag.DOCKER_CONE_CLIENT_1], 5000),
        )
    elif ping_type == PingType.PONG:
        # Send a PONG type message
        ping.message_type = ping.PONG  # pylint: disable=no-member
        sock.sendto(
            struct.pack(">BBB", 9, 0, 3) + ping.SerializeToString(),
            (LAN_ADDR_MAP[ConnectionTag.DOCKER_CONE_CLIENT_1], 5000),
        )
    else:
        sock.sendto(
            struct.pack(">BBBBBBBBBBBB", 4, 0, 8, 17, 9, 0, 0, 0, 0, 0, 0, 0),
            (LAN_ADDR_MAP[ConnectionTag.DOCKER_CONE_CLIENT_1], 5000),
        )


@pytest.mark.asyncio
async def test_ping_pong() -> None:
    async with AsyncExitStack() as exit_stack:
        env = await setup_mesh_nodes(
            exit_stack,
            [SetupParameters(connection_tag=ConnectionTag.DOCKER_CONE_CLIENT_1)],
        )
        client_alpha, *_ = env.clients

        pinger_event = client_alpha.wait_for_output("Pinger")
        ponger_event = client_alpha.wait_for_output("Ponger")

        # Send PING type message
        await exit_stack.enter_async_context(
            run_async_context(client_alpha.receive_ping())
        )
        await send_ping_pong(PingType.PING)

        # Send PONG type message
        await exit_stack.enter_async_context(
            run_async_context(client_alpha.receive_ping())
        )
        await send_ping_pong(PingType.PONG)

        await pinger_event.wait()
        await ponger_event.wait()


@pytest.mark.asyncio
async def test_send_malform_pinger_packet() -> None:
    async with AsyncExitStack() as exit_stack:
        env = await setup_mesh_nodes(
            exit_stack,
            [SetupParameters(connection_tag=ConnectionTag.DOCKER_CONE_CLIENT_1)],
        )
        client_alpha, *_ = env.clients

        unexpected_packet_event = client_alpha.wait_for_output("Unexpected packet: ")

        # Send malformed PingerMsg
        await exit_stack.enter_async_context(
            run_async_context(client_alpha.receive_ping())
        )
        await send_ping_pong(PingType.MALFORMED)
        await unexpected_packet_event.wait()
