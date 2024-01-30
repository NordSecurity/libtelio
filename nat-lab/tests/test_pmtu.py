import config
import pytest
from contextlib import AsyncExitStack
from helpers import SetupParameters, setup_environment
from utils import testing
from utils.connection_util import ConnectionTag
from utils.router import IPStack


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "setup_params",
    [
        pytest.param(
            SetupParameters(
                ip_stack=IPStack.IPv4,
                connection_tag=ConnectionTag.DOCKER_CONE_CLIENT_1,
            )
        ),
        pytest.param(
            SetupParameters(
                ip_stack=IPStack.IPv6,
                connection_tag=ConnectionTag.DOCKER_CONE_CLIENT_1,
            )
        ),
        pytest.param(
            SetupParameters(
                ip_stack=IPStack.IPv4,
                connection_tag=ConnectionTag.MAC_VM,
            )
        ),
        pytest.param(
            SetupParameters(
                ip_stack=IPStack.IPv6,
                connection_tag=ConnectionTag.MAC_VM,
            )
        ),
    ],
)
async def test_pmtu_back_hole(setup_params: SetupParameters) -> None:
    async with AsyncExitStack() as exit_stack:
        env = await exit_stack.enter_async_context(
            setup_environment(exit_stack, [setup_params])
        )
        client, *_ = env.clients

        host = (
            config.PMTU_PROBE_HOST_IP4
            if setup_params.ip_stack in [IPStack.IPv4, IPStack.IPv4v6]
            else config.PMTU_PROBE_HOST_IP6
        )

        await testing.wait_lengthy(client.probe_pmtu(host, 1300))

        # do it second time bacause the kernel might cache something
        await testing.wait_lengthy(client.probe_pmtu(host, 1300))


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "setup_params",
    [
        pytest.param(
            SetupParameters(
                ip_stack=IPStack.IPv4,
                connection_tag=ConnectionTag.DOCKER_CONE_CLIENT_1,
            )
        ),
        pytest.param(
            SetupParameters(
                ip_stack=IPStack.IPv6,
                connection_tag=ConnectionTag.DOCKER_CONE_CLIENT_1,
            )
        ),
        pytest.param(
            SetupParameters(
                ip_stack=IPStack.IPv4,
                connection_tag=ConnectionTag.MAC_VM,
            )
        ),
        pytest.param(
            SetupParameters(
                ip_stack=IPStack.IPv6,
                connection_tag=ConnectionTag.MAC_VM,
            )
        ),
    ],
)
async def test_pmtu_with_nexthop(setup_params: SetupParameters) -> None:
    async with AsyncExitStack() as exit_stack:
        env = await exit_stack.enter_async_context(
            setup_environment(exit_stack, [setup_params])
        )
        client, *_ = env.clients
        connection, *_ = [conn.connection for conn in env.connections]

        host = (
            config.PMTU_PROBE_HOST_IP4
            if setup_params.ip_stack in [IPStack.IPv4, IPStack.IPv4v6]
            else config.PMTU_PROBE_HOST_IP6
        )

        proc = connection.create_process(
            ["python3", "/opt/bin/inject-icmp-host-unreachable"]
        )
        await exit_stack.enter_async_context(proc.run())
        await testing.wait_short(proc.wait_stdin_ready())

        await testing.wait_lengthy(client.probe_pmtu(host, 1300))

        # do it second time bacause the kernel might cache something
        await testing.wait_lengthy(client.probe_pmtu(host, 1300))


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "setup_params",
    [
        pytest.param(
            SetupParameters(
                ip_stack=IPStack.IPv4,
                connection_tag=ConnectionTag.DOCKER_CONE_CLIENT_1,
            )
        ),
        pytest.param(
            SetupParameters(
                ip_stack=IPStack.IPv6,
                connection_tag=ConnectionTag.DOCKER_CONE_CLIENT_1,
            )
        ),
        pytest.param(
            SetupParameters(
                ip_stack=IPStack.IPv4,
                connection_tag=ConnectionTag.MAC_VM,
            )
        ),
        pytest.param(
            SetupParameters(
                ip_stack=IPStack.IPv6,
                connection_tag=ConnectionTag.MAC_VM,
            )
        ),
    ],
)
async def test_pmtu_without_nexthop(setup_params: SetupParameters) -> None:
    async with AsyncExitStack() as exit_stack:
        env = await exit_stack.enter_async_context(
            setup_environment(exit_stack, [setup_params])
        )
        client, *_ = env.clients
        connection, *_ = [conn.connection for conn in env.connections]

        host = (
            config.PMTU_PROBE_HOST_IP4
            if setup_params.ip_stack in [IPStack.IPv4, IPStack.IPv4v6]
            else config.PMTU_PROBE_HOST_IP6
        )

        proc = connection.create_process(
            ["python3", "/opt/bin/inject-icmp-host-unreachable", "-n"]
        )
        await exit_stack.enter_async_context(proc.run())
        await testing.wait_short(proc.wait_stdin_ready())

        await testing.wait_lengthy(client.probe_pmtu(host, 1300))

        # do it second time bacause the kernel might cache something
        await testing.wait_lengthy(client.probe_pmtu(host, 1300))
