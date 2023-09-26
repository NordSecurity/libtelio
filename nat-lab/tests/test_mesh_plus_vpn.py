import asyncio
import config
import pytest
import telio
from contextlib import AsyncExitStack
from mesh_api import API
from telio import AdapterType, PathType, State
from telio_features import TelioFeatures, Direct
from utils import testing, stun
from utils.connection_tracker import ConnectionLimits
from utils.connection_util import (
    generate_connection_tracker_config,
    ConnectionTag,
    new_connection_with_conn_tracker,
)
from utils.ping import Ping


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "alpha_connection_tag,adapter_type",
    [
        pytest.param(ConnectionTag.DOCKER_CONE_CLIENT_1, AdapterType.BoringTun),
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
            ConnectionTag.WINDOWS_VM, AdapterType.WireguardGo, marks=pytest.mark.windows
        ),
        pytest.param(ConnectionTag.MAC_VM, AdapterType.Default, marks=pytest.mark.mac),
    ],
)
async def test_mesh_plus_vpn_one_peer(
    alpha_connection_tag: ConnectionTag, adapter_type: AdapterType
) -> None:
    async with AsyncExitStack() as exit_stack:
        api = API()

        (alpha, beta) = api.default_config_two_nodes()
        (connection_alpha, alpha_conn_tracker) = await exit_stack.enter_async_context(
            new_connection_with_conn_tracker(
                alpha_connection_tag,
                generate_connection_tracker_config(
                    alpha_connection_tag,
                    derp_1_limits=ConnectionLimits(1, 1),
                    vpn_1_limits=ConnectionLimits(1, 1),
                ),
            )
        )
        (connection_beta, beta_conn_tracker) = await exit_stack.enter_async_context(
            new_connection_with_conn_tracker(
                ConnectionTag.DOCKER_CONE_CLIENT_2,
                generate_connection_tracker_config(
                    ConnectionTag.DOCKER_CONE_CLIENT_2,
                    derp_1_limits=ConnectionLimits(1, 1),
                ),
            )
        )

        client_alpha = await exit_stack.enter_async_context(
            telio.Client(connection_alpha, alpha, adapter_type).run_meshnet(
                api.get_meshmap(alpha.id)
            )
        )

        client_beta = await exit_stack.enter_async_context(
            telio.Client(connection_beta, beta).run_meshnet(api.get_meshmap(beta.id))
        )

        await testing.wait_lengthy(
            asyncio.gather(
                client_alpha.wait_for_state_on_any_derp([State.Connected]),
                client_beta.wait_for_state_on_any_derp([State.Connected]),
                alpha_conn_tracker.wait_for_event("derp_1"),
                beta_conn_tracker.wait_for_event("derp_1"),
            )
        )
        await testing.wait_lengthy(
            asyncio.gather(
                client_alpha.wait_for_state_peer(beta.public_key, [State.Connected]),
                client_beta.wait_for_state_peer(alpha.public_key, [State.Connected]),
            )
        )

        async with Ping(connection_alpha, beta.ip_addresses[0]).run() as ping:
            await testing.wait_long(ping.wait_for_next_ping())

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

        await testing.wait_lengthy(alpha_conn_tracker.wait_for_event("vpn_1"))

        async with Ping(connection_alpha, beta.ip_addresses[0]).run() as ping:
            await testing.wait_long(ping.wait_for_next_ping())

        async with Ping(connection_alpha, config.STUN_SERVER).run() as ping:
            await testing.wait_long(ping.wait_for_next_ping())

        public_ip = await testing.wait_long(
            stun.get(connection_alpha, config.STUN_SERVER)
        )
        assert (
            public_ip == wg_server["ipv4"]
        ), f"wrong public IP when connected to VPN {public_ip}"

        assert alpha_conn_tracker.get_out_of_limits() is None
        assert beta_conn_tracker.get_out_of_limits() is None


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "alpha_connection_tag,adapter_type",
    [
        pytest.param(ConnectionTag.DOCKER_CONE_CLIENT_1, AdapterType.BoringTun),
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
            ConnectionTag.WINDOWS_VM, AdapterType.WireguardGo, marks=pytest.mark.windows
        ),
        pytest.param(ConnectionTag.MAC_VM, AdapterType.Default, marks=pytest.mark.mac),
    ],
)
async def test_mesh_plus_vpn_both_peers(
    alpha_connection_tag: ConnectionTag, adapter_type: AdapterType
) -> None:
    async with AsyncExitStack() as exit_stack:
        api = API()

        (alpha, beta) = api.default_config_two_nodes()
        (connection_alpha, alpha_conn_tracker) = await exit_stack.enter_async_context(
            new_connection_with_conn_tracker(
                alpha_connection_tag,
                generate_connection_tracker_config(
                    alpha_connection_tag,
                    derp_1_limits=ConnectionLimits(1, 1),
                    vpn_1_limits=ConnectionLimits(1, 1),
                ),
            )
        )
        (connection_beta, beta_conn_tracker) = await exit_stack.enter_async_context(
            new_connection_with_conn_tracker(
                ConnectionTag.DOCKER_CONE_CLIENT_2,
                generate_connection_tracker_config(
                    ConnectionTag.DOCKER_CONE_CLIENT_2,
                    derp_1_limits=ConnectionLimits(1, 1),
                    vpn_1_limits=ConnectionLimits(1, 1),
                ),
            )
        )

        client_alpha = await exit_stack.enter_async_context(
            telio.Client(connection_alpha, alpha, adapter_type).run_meshnet(
                api.get_meshmap(alpha.id)
            )
        )

        client_beta = await exit_stack.enter_async_context(
            telio.Client(connection_beta, beta).run_meshnet(api.get_meshmap(beta.id))
        )

        await testing.wait_lengthy(
            asyncio.gather(
                client_alpha.wait_for_state_on_any_derp([State.Connected]),
                client_beta.wait_for_state_on_any_derp([State.Connected]),
                alpha_conn_tracker.wait_for_event("derp_1"),
                beta_conn_tracker.wait_for_event("derp_1"),
            )
        )
        await testing.wait_lengthy(
            asyncio.gather(
                client_alpha.wait_for_state_peer(beta.public_key, [State.Connected]),
                client_beta.wait_for_state_peer(alpha.public_key, [State.Connected]),
            )
        )

        async with Ping(connection_alpha, beta.ip_addresses[0]).run() as ping:
            await testing.wait_long(ping.wait_for_next_ping())

        wg_server = config.WG_SERVER

        await testing.wait_long(
            asyncio.gather(
                client_alpha.connect_to_vpn(
                    wg_server["ipv4"], wg_server["port"], wg_server["public_key"]
                ),
                client_beta.connect_to_vpn(
                    wg_server["ipv4"], wg_server["port"], wg_server["public_key"]
                ),
            )
        )

        await testing.wait_lengthy(
            asyncio.gather(
                client_alpha.wait_for_state_peer(
                    wg_server["public_key"], [State.Connected], [PathType.Direct]
                ),
                client_beta.wait_for_state_peer(
                    wg_server["public_key"], [State.Connected], [PathType.Direct]
                ),
                alpha_conn_tracker.wait_for_event("vpn_1"),
                beta_conn_tracker.wait_for_event("vpn_1"),
            )
        )

        async with Ping(connection_alpha, beta.ip_addresses[0]).run() as ping:
            await testing.wait_long(ping.wait_for_next_ping())
        async with Ping(connection_alpha, config.STUN_SERVER).run() as ping:
            await testing.wait_long(ping.wait_for_next_ping())

        async with Ping(connection_beta, alpha.ip_addresses[0]).run() as ping:
            await testing.wait_long(ping.wait_for_next_ping())
        async with Ping(connection_beta, config.STUN_SERVER).run() as ping:
            await testing.wait_long(ping.wait_for_next_ping())

        for connection in [connection_alpha, connection_beta]:
            public_ip = await testing.wait_long(
                stun.get(connection, config.STUN_SERVER)
            )
            assert (
                public_ip == wg_server["ipv4"]
            ), f"wrong public IP when connected to VPN {public_ip}"

        assert alpha_conn_tracker.get_out_of_limits() is None
        assert beta_conn_tracker.get_out_of_limits() is None


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "alpha_connection_tag,adapter_type,public_ip",
    [
        pytest.param(
            ConnectionTag.DOCKER_CONE_CLIENT_1, AdapterType.BoringTun, "10.0.254.1"
        ),
        pytest.param(
            ConnectionTag.DOCKER_CONE_CLIENT_1,
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
        pytest.param(
            ConnectionTag.MAC_VM,
            AdapterType.Default,
            "10.0.254.7",
            marks=pytest.mark.mac,
        ),
    ],
)
async def test_vpn_plus_mesh(
    alpha_connection_tag: ConnectionTag, adapter_type: AdapterType, public_ip: str
) -> None:
    async with AsyncExitStack() as exit_stack:
        api = API()

        (alpha, beta) = api.default_config_two_nodes()
        (connection_alpha, alpha_conn_tracker) = await exit_stack.enter_async_context(
            new_connection_with_conn_tracker(
                alpha_connection_tag,
                generate_connection_tracker_config(
                    alpha_connection_tag,
                    derp_1_limits=ConnectionLimits(1, 1),
                    vpn_1_limits=ConnectionLimits(1, 1),
                    stun_limits=ConnectionLimits(1, 1),
                ),
            )
        )
        (connection_beta, beta_conn_tracker) = await exit_stack.enter_async_context(
            new_connection_with_conn_tracker(
                ConnectionTag.DOCKER_CONE_CLIENT_2,
                generate_connection_tracker_config(
                    ConnectionTag.DOCKER_CONE_CLIENT_2,
                    derp_1_limits=ConnectionLimits(1, 1),
                ),
            )
        )

        ip = await testing.wait_long(stun.get(connection_alpha, config.STUN_SERVER))
        assert ip == public_ip, f"wrong public IP before connecting to VPN {ip}"

        await testing.wait_long(alpha_conn_tracker.wait_for_event("stun"))

        client_alpha = await exit_stack.enter_async_context(
            telio.Client(connection_alpha, alpha, adapter_type).run()
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

        await testing.wait_long(alpha_conn_tracker.wait_for_event("vpn_1"))

        async with Ping(connection_alpha, config.PHOTO_ALBUM_IP).run() as ping:
            await testing.wait_long(ping.wait_for_next_ping())

        ip = await testing.wait_long(stun.get(connection_alpha, config.STUN_SERVER))
        assert ip == wg_server["ipv4"], f"wrong public IP when connected to VPN {ip}"

        await client_alpha.set_meshmap(api.get_meshmap(alpha.id))

        client_beta = await exit_stack.enter_async_context(
            telio.Client(connection_beta, beta).run_meshnet(api.get_meshmap(beta.id))
        )

        await testing.wait_lengthy(
            asyncio.gather(
                client_alpha.wait_for_state_on_any_derp([State.Connected]),
                client_beta.wait_for_state_on_any_derp([State.Connected]),
                alpha_conn_tracker.wait_for_event("derp_1"),
                beta_conn_tracker.wait_for_event("derp_1"),
            )
        )
        await testing.wait_lengthy(
            asyncio.gather(
                client_alpha.wait_for_state_peer(beta.public_key, [State.Connected]),
                client_beta.wait_for_state_peer(alpha.public_key, [State.Connected]),
            )
        )

        async with Ping(connection_alpha, beta.ip_addresses[0]).run() as ping:
            await testing.wait_long(ping.wait_for_next_ping())

        assert alpha_conn_tracker.get_out_of_limits() is None
        assert beta_conn_tracker.get_out_of_limits() is None


@pytest.mark.asyncio
@pytest.mark.timeout(150)
@pytest.mark.parametrize(
    "alpha_connection_tag,adapter_type",
    [
        pytest.param(ConnectionTag.DOCKER_CONE_CLIENT_1, AdapterType.BoringTun),
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
            marks=[
                pytest.mark.windows,
                pytest.mark.xfail(reason="Test is flaky - LLT-4313"),
            ],
        ),
        pytest.param(ConnectionTag.MAC_VM, AdapterType.Default, marks=pytest.mark.mac),
    ],
)
async def test_vpn_plus_mesh_over_direct(
    alpha_connection_tag: ConnectionTag, adapter_type: AdapterType
) -> None:
    async with AsyncExitStack() as exit_stack:
        api = API()
        (alpha, beta) = api.default_config_two_nodes()
        (connection_alpha, alpha_conn_tracker) = await exit_stack.enter_async_context(
            new_connection_with_conn_tracker(
                alpha_connection_tag,
                generate_connection_tracker_config(
                    alpha_connection_tag,
                    derp_1_limits=ConnectionLimits(1, 1),
                    vpn_1_limits=ConnectionLimits(1, 1),
                ),
            )
        )
        (connection_beta, beta_conn_tracker) = await exit_stack.enter_async_context(
            new_connection_with_conn_tracker(
                ConnectionTag.DOCKER_CONE_CLIENT_2,
                generate_connection_tracker_config(
                    ConnectionTag.DOCKER_CONE_CLIENT_2,
                    derp_1_limits=ConnectionLimits(1, 1),
                    vpn_1_limits=ConnectionLimits(1, 1),
                ),
            )
        )

        client_alpha = await exit_stack.enter_async_context(
            telio.Client(
                connection_alpha,
                alpha,
                adapter_type,
                telio_features=TelioFeatures(
                    direct=Direct(providers=["local", "stun"])
                ),
            ).run_meshnet(api.get_meshmap(alpha.id))
        )

        client_beta = await exit_stack.enter_async_context(
            telio.Client(
                connection_beta,
                beta,
                telio_features=TelioFeatures(
                    direct=Direct(providers=["local", "stun"])
                ),
            ).run_meshnet(api.get_meshmap(beta.id))
        )

        await testing.wait_lengthy(
            asyncio.gather(
                client_alpha.wait_for_state_on_any_derp([State.Connected]),
                client_beta.wait_for_state_on_any_derp([State.Connected]),
                alpha_conn_tracker.wait_for_event("derp_1"),
                beta_conn_tracker.wait_for_event("derp_1"),
            )
        )
        await testing.wait_defined(
            asyncio.gather(
                client_alpha.wait_for_state_peer(
                    beta.public_key, [State.Connected], [PathType.Direct]
                ),
                client_beta.wait_for_state_peer(
                    alpha.public_key, [State.Connected], [PathType.Direct]
                ),
            ),
            60,
        )

        async with Ping(connection_alpha, beta.ip_addresses[0]).run() as ping:
            await testing.wait_lengthy(ping.wait_for_next_ping())
        async with Ping(connection_beta, alpha.ip_addresses[0]).run() as ping:
            await testing.wait_lengthy(ping.wait_for_next_ping())

        wg_server = config.WG_SERVER

        await testing.wait_long(
            asyncio.gather(
                client_alpha.connect_to_vpn(
                    wg_server["ipv4"], wg_server["port"], wg_server["public_key"]
                ),
                client_beta.connect_to_vpn(
                    wg_server["ipv4"], wg_server["port"], wg_server["public_key"]
                ),
            )
        )
        await testing.wait_lengthy(
            asyncio.gather(
                client_alpha.wait_for_state_peer(
                    wg_server["public_key"], [State.Connected], [PathType.Direct]
                ),
                client_beta.wait_for_state_peer(
                    wg_server["public_key"], [State.Connected], [PathType.Direct]
                ),
                alpha_conn_tracker.wait_for_event("vpn_1"),
                beta_conn_tracker.wait_for_event("vpn_1"),
            )
        )

        async with Ping(connection_alpha, beta.ip_addresses[0]).run() as ping:
            # TODO: change waiting time to `wait_long` after issue LLT-3879 is fixed
            await testing.wait_defined(ping.wait_for_next_ping(), 60)
        async with Ping(connection_alpha, config.STUN_SERVER).run() as ping:
            await testing.wait_long(ping.wait_for_next_ping())

        async with Ping(connection_beta, alpha.ip_addresses[0]).run() as ping:
            # TODO: change waiting time to `wait_long` after issue LLT-3879 is fixed
            await testing.wait_defined(ping.wait_for_next_ping(), 60)
        async with Ping(connection_beta, config.STUN_SERVER).run() as ping:
            await testing.wait_long(ping.wait_for_next_ping())

        for connection in [connection_alpha, connection_beta]:
            public_ip = await testing.wait_long(
                stun.get(connection, config.STUN_SERVER)
            )
            assert (
                public_ip == wg_server["ipv4"]
            ), f"wrong public IP when connected to VPN {public_ip}"

        assert alpha_conn_tracker.get_out_of_limits() is None
        assert beta_conn_tracker.get_out_of_limits() is None


@pytest.mark.asyncio
@pytest.mark.timeout(150)
@pytest.mark.parametrize(
    "alpha_connection_tag,adapter_type",
    [
        pytest.param(ConnectionTag.DOCKER_CONE_CLIENT_1, AdapterType.BoringTun),
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
            marks=[
                pytest.mark.windows,
                pytest.mark.xfail(reason="test is flaky - LLT-4314"),
            ],
        ),
        pytest.param(
            ConnectionTag.MAC_VM,
            AdapterType.Default,
            marks=[
                pytest.mark.mac,
                pytest.mark.xfail(reason="test is flaky - LLT-4116"),
            ],
        ),
    ],
)
async def test_vpn_plus_mesh_over_different_connection_types(
    alpha_connection_tag: ConnectionTag, adapter_type: AdapterType
) -> None:
    async with AsyncExitStack() as exit_stack:
        api = API()

        (alpha, beta, gamma) = api.default_config_three_nodes()
        (connection_alpha, alpha_conn_tracker) = await exit_stack.enter_async_context(
            new_connection_with_conn_tracker(
                alpha_connection_tag,
                generate_connection_tracker_config(
                    alpha_connection_tag,
                    derp_1_limits=ConnectionLimits(1, 1),
                    vpn_1_limits=ConnectionLimits(1, 1),
                ),
            )
        )
        (connection_beta, beta_conn_tracker) = await exit_stack.enter_async_context(
            new_connection_with_conn_tracker(
                ConnectionTag.DOCKER_CONE_CLIENT_2,
                generate_connection_tracker_config(
                    ConnectionTag.DOCKER_CONE_CLIENT_2,
                    derp_1_limits=ConnectionLimits(1, 1),
                    vpn_1_limits=ConnectionLimits(1, 1),
                ),
            )
        )
        (connection_gamma, gamma_conn_tracker) = await exit_stack.enter_async_context(
            new_connection_with_conn_tracker(
                ConnectionTag.DOCKER_SYMMETRIC_CLIENT_1,
                generate_connection_tracker_config(
                    ConnectionTag.DOCKER_SYMMETRIC_CLIENT_1,
                    derp_1_limits=ConnectionLimits(1, 1),
                    vpn_1_limits=ConnectionLimits(1, 1),
                ),
            )
        )

        client_alpha = await exit_stack.enter_async_context(
            telio.Client(
                connection_alpha,
                alpha,
                adapter_type,
                telio_features=TelioFeatures(
                    direct=Direct(providers=["local", "stun"])
                ),
            ).run_meshnet(api.get_meshmap(alpha.id))
        )

        client_beta = await exit_stack.enter_async_context(
            telio.Client(
                connection_beta,
                beta,
                telio_features=TelioFeatures(
                    direct=Direct(providers=["local", "stun"])
                ),
            ).run_meshnet(api.get_meshmap(beta.id))
        )

        client_gamma = await exit_stack.enter_async_context(
            telio.Client(connection_gamma, gamma).run_meshnet(api.get_meshmap(gamma.id))
        )

        await testing.wait_lengthy(
            asyncio.gather(
                client_alpha.wait_for_state_on_any_derp([State.Connected]),
                client_beta.wait_for_state_on_any_derp([State.Connected]),
                client_gamma.wait_for_state_on_any_derp([State.Connected]),
                alpha_conn_tracker.wait_for_event("derp_1"),
                beta_conn_tracker.wait_for_event("derp_1"),
                gamma_conn_tracker.wait_for_event("derp_1"),
            )
        )
        await testing.wait_lengthy(
            asyncio.gather(
                client_alpha.wait_for_state_peer(gamma.public_key, [State.Connected]),
                client_gamma.wait_for_state_peer(alpha.public_key, [State.Connected]),
                client_beta.wait_for_state_peer(gamma.public_key, [State.Connected]),
                client_gamma.wait_for_state_peer(beta.public_key, [State.Connected]),
            )
        )

        await testing.wait_defined(
            asyncio.gather(
                client_alpha.wait_for_state_peer(
                    beta.public_key, [State.Connected], [PathType.Direct]
                ),
                client_beta.wait_for_state_peer(
                    alpha.public_key, [State.Connected], [PathType.Direct]
                ),
            ),
            60,
        )

        async with Ping(connection_alpha, beta.ip_addresses[0]).run() as ping:
            await testing.wait_lengthy(ping.wait_for_next_ping())
        async with Ping(connection_alpha, gamma.ip_addresses[0]).run() as ping:
            await testing.wait_lengthy(ping.wait_for_next_ping())

        wg_server = config.WG_SERVER

        await testing.wait_long(
            asyncio.gather(
                client_alpha.connect_to_vpn(
                    wg_server["ipv4"], wg_server["port"], wg_server["public_key"]
                ),
                client_beta.connect_to_vpn(
                    wg_server["ipv4"], wg_server["port"], wg_server["public_key"]
                ),
                client_gamma.connect_to_vpn(
                    wg_server["ipv4"], wg_server["port"], wg_server["public_key"]
                ),
            )
        )

        await testing.wait_lengthy(
            asyncio.gather(
                client_alpha.wait_for_state_peer(
                    wg_server["public_key"], [State.Connected], [PathType.Direct]
                ),
                client_beta.wait_for_state_peer(
                    wg_server["public_key"], [State.Connected], [PathType.Direct]
                ),
                client_gamma.wait_for_state_peer(
                    wg_server["public_key"], [State.Connected], [PathType.Direct]
                ),
                alpha_conn_tracker.wait_for_event("vpn_1"),
                beta_conn_tracker.wait_for_event("vpn_1"),
                gamma_conn_tracker.wait_for_event("vpn_1"),
            )
        )

        async with Ping(connection_alpha, beta.ip_addresses[0]).run() as ping:
            # TODO: change waiting time to `wait_long` after issue LLT-3879 is fixed
            await testing.wait_defined(ping.wait_for_next_ping(), 60)
        async with Ping(connection_alpha, gamma.ip_addresses[0]).run() as ping:
            await testing.wait_long(ping.wait_for_next_ping())
        async with Ping(connection_alpha, config.STUN_SERVER).run() as ping:
            await testing.wait_long(ping.wait_for_next_ping())

        async with Ping(connection_beta, alpha.ip_addresses[0]).run() as ping:
            # TODO: change waiting time to `wait_long` after issue LLT-3879 is fixed
            await testing.wait_defined(ping.wait_for_next_ping(), 60)
        async with Ping(connection_beta, config.STUN_SERVER).run() as ping:
            await testing.wait_long(ping.wait_for_next_ping())

        async with Ping(connection_gamma, alpha.ip_addresses[0]).run() as ping:
            await testing.wait_long(ping.wait_for_next_ping())
        async with Ping(connection_gamma, config.STUN_SERVER).run() as ping:
            await testing.wait_long(ping.wait_for_next_ping())

        for connection in [connection_alpha, connection_beta, connection_gamma]:
            public_ip = await testing.wait_long(
                stun.get(connection, config.STUN_SERVER)
            )
            assert (
                public_ip == wg_server["ipv4"]
            ), f"wrong public IP when connected to VPN {public_ip}"

        assert alpha_conn_tracker.get_out_of_limits() is None
        assert beta_conn_tracker.get_out_of_limits() is None
