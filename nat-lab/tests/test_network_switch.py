from utils import Ping, stun
from contextlib import AsyncExitStack
from mesh_api import API
from config import DERP_PRIMARY, DERP_SECONDARY, DERP_TERTIARY, DERP_SERVERS
from telio import AdapterType, PathType
from telio_features import TelioFeatures, Direct
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
            "10.0.254.13",
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

        (alpha, beta) = api.default_config_two_nodes()
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

        async with Ping(connection_alpha, beta.ip_addresses[0]) as ping:
            await testing.wait_long(ping.wait_for_next_ping())

        await network_switcher.switch_to_secondary_network()
        await client_alpha.notify_network_change()

        async with Ping(connection_alpha, beta.ip_addresses[0]) as ping:
            await testing.wait_long(ping.wait_for_next_ping())


@pytest.mark.asyncio
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

        alpha = api.default_config_alpha_node()
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

        async with Ping(connection, config.PHOTO_ALBUM_IP) as ping:
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

        async with Ping(connection, config.PHOTO_ALBUM_IP) as ping:
            await testing.wait_long(ping.wait_for_next_ping())

        ip = await testing.wait_long(stun.get(connection, config.STUN_SERVER))
        assert ip == wg_server["ipv4"], f"wrong public IP when connected to VPN {ip}"


@pytest.mark.asyncio
@pytest.mark.timeout(150)
@pytest.mark.parametrize(
    "endpoint_providers, alpha_connection_tag, adapter_type, notify_network_change",
    [
        pytest.param(
            ["stun"],
            ConnectionTag.DOCKER_SHARED_CLIENT_1,
            AdapterType.BoringTun,
            True,
        ),
        pytest.param(
            ["stun"],
            ConnectionTag.DOCKER_SHARED_CLIENT_1,
            AdapterType.LinuxNativeWg,
            True,
            marks=pytest.mark.linux_native,
        ),
        # Windows test cases are temporarily disabled because they are flaky
        # see LLT-3946
        #
        # pytest.param(
        #     ["stun"],
        #     ConnectionTag.WINDOWS_VM,
        #     AdapterType.WindowsNativeWg,
        #     True,
        #     marks=pytest.mark.windows,
        # ),
        # pytest.param(
        #     ["stun"],
        #     ConnectionTag.WINDOWS_VM,
        #     AdapterType.WireguardGo,
        #     True,
        #     marks=pytest.mark.windows,
        # ),
    ],
)
async def test_mesh_network_switch_direct(
    endpoint_providers, alpha_connection_tag, adapter_type, notify_network_change
) -> None:
    async with AsyncExitStack() as exit_stack:
        api = API()
        (alpha, beta) = api.default_config_two_nodes()

        (alpha_connection, network_switcher) = await exit_stack.enter_async_context(
            new_connection_with_network_switcher(alpha_connection_tag)
        )
        assert network_switcher

        beta_connection = await exit_stack.enter_async_context(
            new_connection_by_tag(ConnectionTag.DOCKER_CONE_CLIENT_2)
        )

        alpha_client = await exit_stack.enter_async_context(
            telio.run_meshnet(
                alpha_connection,
                alpha,
                api.get_meshmap(alpha.id),
                adapter_type,
                telio_features=TelioFeatures(
                    direct=Direct(providers=endpoint_providers)
                ),
            )
        )

        beta_client = await exit_stack.enter_async_context(
            telio.run_meshnet(
                beta_connection,
                beta,
                api.get_meshmap(beta.id),
                telio.AdapterType.BoringTun,
                telio_features=TelioFeatures(
                    direct=Direct(providers=endpoint_providers)
                ),
            )
        )

        await testing.wait_lengthy(
            asyncio.gather(
                alpha_client.wait_for_any_derp_state(
                    [telio.State.Connected],
                ),
                beta_client.wait_for_any_derp_state(
                    [telio.State.Connected],
                ),
            ),
        )

        await testing.wait_lengthy(
            asyncio.gather(
                alpha_client.handshake(
                    beta.public_key,
                    telio.PathType.Direct,
                ),
                beta_client.handshake(
                    alpha.public_key,
                    telio.PathType.Direct,
                ),
            ),
        )

        async with Ping(alpha_connection, beta.ip_addresses[0]) as ping:
            await testing.wait_long(ping.wait_for_next_ping())

        await network_switcher.switch_to_secondary_network()

        await alpha_client.notify_network_change()

        await testing.wait_lengthy(
            alpha_client.wait_for_any_derp_state(
                [telio.State.Connected],
            ),
        )

        await testing.wait_lengthy(
            asyncio.gather(
                alpha_client.handshake(
                    beta.public_key,
                    telio.PathType.Direct,
                ),
                beta_client.handshake(
                    alpha.public_key,
                    telio.PathType.Direct,
                ),
            ),
        )

        async with Ping(alpha_connection, beta.ip_addresses[0]) as ping:
            await testing.wait_lengthy(ping.wait_for_next_ping())
