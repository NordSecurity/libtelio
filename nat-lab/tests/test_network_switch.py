from utils import Ping, stun
from contextlib import AsyncExitStack
from mesh_api import API
from telio import AdapterType, PathType
import asyncio
import config
import pytest
import telio
import utils.testing as testing

from utils import (
    ConnectionTag,
    new_connection_by_tag,
    new_connection_with_network_switcher,
)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "connection_tag, primary_ip, secondary_ip",
    [
        pytest.param(
            ConnectionTag.DOCKER_SHARED_CLIENT_1,
            "10.0.254.1",
            "10.0.254.2",
        ),
        pytest.param(
            ConnectionTag.WINDOWS_VM,
            "10.0.254.7",
            "10.0.254.8",
            marks=pytest.mark.windows,
        ),
        pytest.param(
            ConnectionTag.MAC_VM,
            "10.0.254.7",
            "10.0.254.8",
            marks=[
                pytest.mark.mac,
                pytest.mark.skip(reason="the test is flaky - JIRA issue: LLT-2393"),
            ],
        ),
    ],
)
async def test_network_switcher(
    connection_tag: ConnectionTag, primary_ip: str, secondary_ip: str
) -> None:
    async with new_connection_with_network_switcher(connection_tag) as (
        connection,
        network_switcher,
    ):
        assert await stun.get(connection, config.STUN_SERVER) == primary_ip

        assert network_switcher
        await network_switcher.switch_to_secondary_network()

        assert await stun.get(connection, config.STUN_SERVER) == secondary_ip


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "alpha_connection_tag, adapter_type",
    [
        pytest.param(
            ConnectionTag.DOCKER_SHARED_CLIENT_1,
            AdapterType.BoringTun,
        ),
        pytest.param(
            ConnectionTag.DOCKER_SHARED_CLIENT_1,
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
        # JIRA issue: LLT-1134
        # pytest.param(
        #     ConnectionTag.MAC_VM,
        #     AdapterType.Default,
        #     marks=pytest.mark.mac,
        # ),
    ],
)
async def test_mesh_network_switch(
    alpha_connection_tag: ConnectionTag, adapter_type: AdapterType
) -> None:
    async with AsyncExitStack() as exit_stack:
        api = API()

        alpha = api.register(
            name="alpha",
            id="96ddb926-4b86-11ec-81d3-0242ac130003",
            private_key="JcnzdKlaRd56T/EnHkbVpNCvYo64YLDpRZsJq14ZU1A=",
            public_key="eES5D8OiQyMXf/pG0ibJSD2QhSnKLW0+6jW7mvtfL0g=",
        )

        beta = api.register(
            name="beta",
            id="7b4548ca-fe5a-4597-8513-896f38c6d6ae",
            private_key="+KqbDiS4KkWlB1iI9DfAnQTX7+c4YvFQzlLQWljbVHc=",
            public_key="5eURKcx0OlMyz2kXOibfHklUwF9pgplc0eBdlo4B3gk=",
        )

        api.assign_ip(alpha.id, "100.64.0.11")
        api.assign_ip(beta.id, "100.64.0.22")

        beta.set_peer_firewall_settings(alpha.id, allow_incoming_connections=True)

        (connection_alpha, network_switcher) = await exit_stack.enter_async_context(
            new_connection_with_network_switcher(alpha_connection_tag)
        )
        assert network_switcher

        client_alpha = await exit_stack.enter_async_context(
            telio.run_meshnet(
                connection_alpha,
                alpha,
                api.get_meshmap(alpha.id),
                adapter_type,
            )
        )

        client_beta = await exit_stack.enter_async_context(
            telio.run_meshnet(
                await exit_stack.enter_async_context(
                    new_connection_by_tag(ConnectionTag.DOCKER_SYMMETRIC_CLIENT_1)
                ),
                beta,
                api.get_meshmap(beta.id),
            )
        )

        await testing.wait_long(client_alpha.handshake(beta.public_key))
        await testing.wait_long(client_beta.handshake(alpha.public_key))

        async with Ping(connection_alpha, "100.64.0.22") as ping:
            await testing.wait_long(ping.wait_for_next_ping())

        await network_switcher.switch_to_secondary_network()
        await client_alpha.notify_network_change()

        async with Ping(connection_alpha, "100.64.0.22") as ping:
            await testing.wait_long(ping.wait_for_next_ping())


@pytest.mark.asyncio
@pytest.mark.vpn
@pytest.mark.parametrize(
    "connection_tag,adapter_type,public_ip",
    [
        pytest.param(
            ConnectionTag.DOCKER_SHARED_CLIENT_1,
            AdapterType.BoringTun,
            "10.0.254.1",
        ),
        pytest.param(
            ConnectionTag.DOCKER_SHARED_CLIENT_1,
            AdapterType.LinuxNativeWg,
            "10.0.254.1",
            marks=pytest.mark.linux_native,
        ),
        pytest.param(
            ConnectionTag.WINDOWS_VM,
            AdapterType.WindowsNativeWg,
            "10.0.254.7",
            marks=pytest.mark.windows,
        ),
        pytest.param(
            ConnectionTag.WINDOWS_VM,
            AdapterType.WireguardGo,
            "10.0.254.7",
            marks=pytest.mark.windows,
        ),
        # JIRA issue: LLT-1134
        # pytest.param(
        #     ConnectionTag.MAC_VM,
        #     AdapterType.Default,
        #     "10.0.254.7",
        #     marks=pytest.mark.mac,
        # ),
    ],
)
async def test_vpn_network_switch(
    connection_tag: ConnectionTag, adapter_type: AdapterType, public_ip: str
) -> None:
    async with AsyncExitStack() as exit_stack:
        api = API()

        alpha = api.register(
            name="alpha",
            id="96ddb926-4b86-11ec-81d3-0242ac130003",
            private_key="CIDMCmjr6XSIZp6hnogYSlTYJNeFJmXgf28f27HKCXw=",
            public_key="655Gn59wY0AbzIvUfQPFSCJkQOhrg6gszlxeVKPIlgw=",
        )

        api.assign_ip(alpha.id, "100.64.33.4")

        (connection, network_switcher) = await exit_stack.enter_async_context(
            new_connection_with_network_switcher(connection_tag)
        )
        assert network_switcher

        client_alpha = await exit_stack.enter_async_context(
            telio.run(
                connection,
                alpha,
                adapter_type,
            )
        )

        wg_server = config.WG_SERVER

        await testing.wait_long(
            client_alpha.connect_to_vpn(
                wg_server["ipv4"], wg_server["port"], wg_server["public_key"]
            )
        )
        await testing.wait_lengthy(
            client_alpha.handshake(wg_server["public_key"], PathType.Direct)
        )

        async with Ping(connection, "10.0.80.80") as ping:
            await testing.wait_long(ping.wait_for_next_ping())

        ip = await testing.wait_long(stun.get(connection, config.STUN_SERVER))
        assert ip == wg_server["ipv4"], f"wrong public IP when connected to VPN {ip}"

        await network_switcher.switch_to_secondary_network()
        await client_alpha.notify_network_change()

        # This is really silly.. For some reason, adding a short sleep here allows the VPN
        # connection to be restored faster. The difference is almost 5 seconds. Without
        # the sleep, the test fails often due to timeouts. Its as if feeding data into
        # a connection, which is being restored, bogs down the connection and it takes
        # more time for the connection to be restored.
        if connection_tag == ConnectionTag.WINDOWS_VM:
            await asyncio.sleep(1.0)

        async with Ping(connection, "10.0.80.80") as ping:
            await testing.wait_long(ping.wait_for_next_ping())

        ip = await testing.wait_long(stun.get(connection, config.STUN_SERVER))
        assert ip == wg_server["ipv4"], f"wrong public IP when connected to VPN {ip}"
