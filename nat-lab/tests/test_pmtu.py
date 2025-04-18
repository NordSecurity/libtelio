import config
import pytest
from contextlib import AsyncExitStack
from helpers import SetupParameters, setup_environment, setup_connections
from utils import stun
from utils.bindings import (
    default_features,
    Features,
    FeaturePmtuDiscovery,
    TelioAdapterType,
)
from utils.connection import ConnectionTag
from utils.connection_util import generate_connection_tracker_config
from utils.ping import ping
from utils.router import IPStack


def features() -> Features:
    f = default_features()
    f.pmtu_discovery = FeaturePmtuDiscovery(response_wait_timeout_s=1)
    return f


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "setup_params",
    [
        pytest.param(
            SetupParameters(
                ip_stack=IPStack.IPv4,
                connection_tag=ConnectionTag.DOCKER_CONE_CLIENT_1,
                features=features(),
            )
        ),
        # TODO(msz): Disable IPv6 tests since the docker netowrk uses local link addresses
        #            causing `connect()` call to fail.
        # pytest.param(
        #     SetupParameters(
        #         ip_stack=IPStack.IPv6,
        #         connection_tag=ConnectionTag.DOCKER_CONE_CLIENT_1,
        #     )
        # ),
    ],
)
async def test_pmtu_black_hole(setup_params: SetupParameters) -> None:
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

        assert await client.probe_pmtu(host) == 1300

        # do it second time bacause the kernel might cache something
        assert await client.probe_pmtu(host) == 1300


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "setup_params",
    [
        pytest.param(
            SetupParameters(
                ip_stack=IPStack.IPv4,
                connection_tag=ConnectionTag.DOCKER_CONE_CLIENT_1,
                features=features(),
            )
        ),
        # TODO(msz): Disable IPv6 tests since the docker netowrk uses local link addresses
        #            causing `connect()` call to fail.
        # pytest.param(
        #     SetupParameters(
        #         ip_stack=IPStack.IPv6,
        #         connection_tag=ConnectionTag.DOCKER_CONE_CLIENT_1,
        #     )
        # ),
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

        proc = connection.create_process(["/opt/bin/inject-icmp-host-unreachable"])
        await exit_stack.enter_async_context(proc.run())
        await proc.wait_stdin_ready()

        assert await client.probe_pmtu(host) == 1300

        # do it second time bacause the kernel might cache something
        assert await client.probe_pmtu(host) == 1300


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "setup_params",
    [
        pytest.param(
            SetupParameters(
                ip_stack=IPStack.IPv4,
                connection_tag=ConnectionTag.DOCKER_CONE_CLIENT_1,
                features=features(),
            )
        ),
        # TODO(msz): Disable IPv6 tests since the docker netowrk uses local link addresses
        #            causing `connect()` call to fail.
        # pytest.param(
        #     SetupParameters(
        #         ip_stack=IPStack.IPv6,
        #         connection_tag=ConnectionTag.DOCKER_CONE_CLIENT_1,
        #     )
        # ),
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
            ["/opt/bin/inject-icmp-host-unreachable", "-n"]
        )
        await exit_stack.enter_async_context(proc.run())
        await proc.wait_stdin_ready()

        assert await client.probe_pmtu(host) == 1300

        # do it second time bacause the kernel might cache something
        assert await client.probe_pmtu(host) == 1300


# Test vpn connection with PMTU available, expect conntracker to detect PMTU ICMP connection
@pytest.mark.asyncio
@pytest.mark.parametrize(
    "params",
    [
        pytest.param(
            SetupParameters(
                adapter_type_override=TelioAdapterType.NEP_TUN,
                connection_tracker_config=generate_connection_tracker_config(
                    ConnectionTag.DOCKER_CONE_CLIENT_1,
                    vpn_1_limits=(1, 1),
                    stun_limits=(1, 1),
                    ping_limits=(1, 1),
                ),
                features=features(),
                is_meshnet=False,
            ),
        ),
        pytest.param(
            SetupParameters(
                adapter_type_override=TelioAdapterType.LINUX_NATIVE_TUN,
                connection_tracker_config=generate_connection_tracker_config(
                    ConnectionTag.DOCKER_CONE_CLIENT_1,
                    vpn_1_limits=(1, 1),
                    stun_limits=(1, 1),
                    ping_limits=(1, 1),
                ),
                features=features(),
                is_meshnet=False,
            ),
            marks=pytest.mark.linux_native,
        ),
    ],
)
async def test_vpn_conn_with_pmtu_enabled(params: SetupParameters) -> None:
    async with AsyncExitStack() as exit_stack:
        env = await exit_stack.enter_async_context(
            setup_environment(exit_stack, [params], prepare_vpn=True)
        )

        alpha, *_ = env.nodes
        connection, *_ = [conn.connection for conn in env.connections]
        client, *_ = env.clients

        vpn_conn, *_ = await setup_connections(exit_stack, [ConnectionTag.DOCKER_VPN_1])

        await stun.get(connection, config.STUN_SERVER)

        await client.connect_to_vpn(
            str(config.WG_SERVER["ipv4"]),
            int(config.WG_SERVER["port"]),
            str(config.WG_SERVER["public_key"]),
        )

        await ping(vpn_conn.connection, alpha.ip_addresses[0])
