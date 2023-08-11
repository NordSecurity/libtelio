import asyncio
import config
import pytest
import telio
from contextlib import AsyncExitStack
from mesh_api import API
from telio import AdapterType, PathType, State
from telio_features import TelioFeatures, Direct
from utils import testing, stun
from utils.connection_util import (
    ConnectionTag,
    new_connection_by_tag,
    new_connection_with_network_switcher,
)
from utils.ping import Ping


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "connection_tag, primary_ip, secondary_ip",
    [
        pytest.param(ConnectionTag.DOCKER_SHARED_CLIENT_1, "10.0.254.1", "10.0.254.13"),
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
                pytest.mark.xfail(reason="the test is flaky - JIRA issue: LLT-2393"),
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
        assert (
            await testing.wait_long(stun.get(connection, config.STUN_SERVER))
            == primary_ip
        )

        assert network_switcher
        await network_switcher.switch_to_secondary_network()

        assert (
            await testing.wait_long(stun.get(connection, config.STUN_SERVER))
            == secondary_ip
        )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "alpha_connection_tag, adapter_type",
    [
        pytest.param(ConnectionTag.DOCKER_SHARED_CLIENT_1, AdapterType.BoringTun),
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
            ConnectionTag.WINDOWS_VM, AdapterType.WireguardGo, marks=pytest.mark.windows
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
        connection_beta = await exit_stack.enter_async_context(
            new_connection_by_tag(ConnectionTag.DOCKER_SYMMETRIC_CLIENT_1)
        )

        client_alpha = await exit_stack.enter_async_context(
            telio.Client(connection_alpha, alpha, adapter_type).run_meshnet(
                api.get_meshmap(alpha.id)
            )
        )

        client_beta = await exit_stack.enter_async_context(
            telio.Client(connection_beta, beta).run_meshnet(api.get_meshmap(beta.id))
        )

        await testing.wait_long(
            client_alpha.wait_for_state_peer(beta.public_key, [State.Connected])
        )
        await testing.wait_long(
            client_beta.wait_for_state_peer(alpha.public_key, [State.Connected])
        )

        async with Ping(connection_alpha, beta.ip_addresses[0]).run() as ping:
            await testing.wait_long(ping.wait_for_next_ping())

        await network_switcher.switch_to_secondary_network()
        await client_alpha.notify_network_change()

        async with Ping(connection_alpha, beta.ip_addresses[0]).run() as ping:
            await testing.wait_long(ping.wait_for_next_ping())


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "connection_tag, adapter_type",
    [
        pytest.param(ConnectionTag.DOCKER_SHARED_CLIENT_1, AdapterType.BoringTun),
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
            ConnectionTag.WINDOWS_VM, AdapterType.WireguardGo, marks=pytest.mark.windows
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
    connection_tag: ConnectionTag, adapter_type: AdapterType
) -> None:
    async with AsyncExitStack() as exit_stack:
        api = API()

        alpha = api.default_config_alpha_node()
        (connection, network_switcher) = await exit_stack.enter_async_context(
            new_connection_with_network_switcher(connection_tag)
        )
        assert network_switcher

        client_alpha = await exit_stack.enter_async_context(
            telio.Client(connection, alpha, adapter_type).run()
        )

        wg_server = config.WG_SERVER

        await testing.wait_long(
            client_alpha.connect_to_vpn(
                wg_server["ipv4"], wg_server["port"], wg_server["public_key"]
            )
        )
        await testing.wait_lengthy(
            client_alpha.wait_for_state_peer(
                wg_server["public_key"], [State.Connected], [PathType.Direct]
            )
        )

        async with Ping(connection, config.PHOTO_ALBUM_IP).run() as ping:
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

        async with Ping(connection, config.PHOTO_ALBUM_IP).run() as ping:
            await testing.wait_long(ping.wait_for_next_ping())

        ip = await testing.wait_long(stun.get(connection, config.STUN_SERVER))
        assert ip == wg_server["ipv4"], f"wrong public IP when connected to VPN {ip}"


@pytest.mark.asyncio
@pytest.mark.timeout(150)
@pytest.mark.parametrize(
    "endpoint_providers, alpha_connection_tag, adapter_type",
    [
        pytest.param(
            ["stun"], ConnectionTag.DOCKER_SHARED_CLIENT_1, AdapterType.BoringTun
        ),
        pytest.param(
            ["stun"],
            ConnectionTag.DOCKER_SHARED_CLIENT_1,
            AdapterType.LinuxNativeWg,
            marks=[
                pytest.mark.linux_native,
                pytest.mark.xfail(
                    reason=(
                        "Flaky: Running tests in specific order, might change the"
                        " result of tests - LLT-4102 / LLT-4105"
                    )
                ),
            ],
        ),
        # Windows test cases are temporarily disabled because they are flaky
        # see LLT-3946
        #
        # pytest.param(
        #     ["stun"],
        #     ConnectionTag.WINDOWS_VM,
        #     AdapterType.WindowsNativeWg,
        #     marks=pytest.mark.windows,
        # ),
        # pytest.param(
        #     ["stun"],
        #     ConnectionTag.WINDOWS_VM,
        #     AdapterType.WireguardGo,
        #     marks=pytest.mark.windows,
        # ),
    ],
)
async def test_mesh_network_switch_direct(
    endpoint_providers, alpha_connection_tag, adapter_type
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
            telio.Client(
                alpha_connection,
                alpha,
                adapter_type,
                telio_features=TelioFeatures(
                    direct=Direct(providers=endpoint_providers)
                ),
            ).run_meshnet(api.get_meshmap(alpha.id))
        )

        beta_client = await exit_stack.enter_async_context(
            telio.Client(
                beta_connection,
                beta,
                AdapterType.BoringTun,
                telio_features=TelioFeatures(
                    direct=Direct(providers=endpoint_providers)
                ),
            ).run_meshnet(api.get_meshmap(beta.id))
        )

        await testing.wait_lengthy(
            asyncio.gather(
                alpha_client.wait_for_state_on_any_derp([State.Connected]),
                beta_client.wait_for_state_on_any_derp([State.Connected]),
            )
        )

        await testing.wait_lengthy(
            asyncio.gather(
                alpha_client.wait_for_state_peer(
                    beta.public_key, [State.Connected], [PathType.Direct]
                ),
                beta_client.wait_for_state_peer(
                    alpha.public_key, [State.Connected], [PathType.Direct]
                ),
            )
        )

        async with Ping(alpha_connection, beta.ip_addresses[0]).run() as ping:
            await testing.wait_long(ping.wait_for_next_ping())

        await network_switcher.switch_to_secondary_network()
        await alpha_client.notify_network_change()

        await testing.wait_lengthy(
            alpha_client.wait_for_event_on_any_derp([State.Connected])
        )

        await testing.wait_lengthy(
            asyncio.gather(
                alpha_client.wait_for_state_peer(
                    beta.public_key, [State.Connected], [PathType.Relay]
                ),
                beta_client.wait_for_state_peer(
                    alpha.public_key, [State.Connected], [PathType.Relay]
                ),
            )
        )
        await testing.wait_lengthy(
            asyncio.gather(
                alpha_client.wait_for_state_peer(
                    beta.public_key, [State.Connected], [PathType.Direct]
                ),
                beta_client.wait_for_state_peer(
                    alpha.public_key, [State.Connected], [PathType.Direct]
                ),
            )
        )

        async with Ping(alpha_connection, beta.ip_addresses[0]).run() as ping:
            await testing.wait_lengthy(ping.wait_for_next_ping())
