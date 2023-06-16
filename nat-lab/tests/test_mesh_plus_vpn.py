from utils import Ping, stun
from config import DERP_PRIMARY
from contextlib import AsyncExitStack
from mesh_api import API
from telio import AdapterType, PathType
from telio_features import TelioFeatures, Direct
from utils import ConnectionTag, new_connection_by_tag
import config
import pytest
import telio
import utils.testing as testing
import asyncio


@pytest.mark.asyncio
@pytest.mark.vpn
@pytest.mark.parametrize(
    "alpha_connection_tag,adapter_type",
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
        # pytest.param(
        #     ConnectionTag.MAC_VM,
        #     AdapterType.Default,
        #     marks=pytest.mark.mac,
        # ),
    ],
)
async def test_mesh_plus_vpn_one_peer(
    alpha_connection_tag: ConnectionTag, adapter_type: AdapterType
) -> None:
    async with AsyncExitStack() as exit_stack:
        api = API()

        alpha = api.register(
            name="alpha",
            id="96ddb926-4b86-11ec-81d3-0242ac130003",
            private_key="IGm+42FLMMGZRaQvk6F3UPbl+T/CBk8W+NPoX2/AdlU=",
            public_key="41CCEssnYIh8/8D8YvbTfWEcFanG3D0I0z1tRcN1Lyc=",
        )

        beta = api.register(
            name="beta",
            id="7b4548ca-fe5a-4597-8513-896f38c6d6ae",
            private_key="SPFD84gPtBNc3iGY9Cdrj+mSCwBeh3mCMWfPaeWQolw=",
            public_key="Q1M3VKUcfTmGsrRzY6BpNds1yDIUvPVcs/2TySv/t1U=",
        )

        api.assign_ip(alpha.id, "100.64.33.2")
        api.assign_ip(beta.id, "100.64.33.3")

        beta.set_peer_firewall_settings(alpha.id, allow_incoming_connections=True)

        connection_alpha = await exit_stack.enter_async_context(
            new_connection_by_tag(alpha_connection_tag)
        )
        connection_beta = await exit_stack.enter_async_context(
            new_connection_by_tag(ConnectionTag.DOCKER_CONE_CLIENT_2)
        )

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
                connection_beta,
                beta,
                api.get_meshmap(beta.id),
            )
        )

        await testing.wait_long(client_alpha.handshake(beta.public_key))
        await testing.wait_long(client_beta.handshake(alpha.public_key))

        async with Ping(connection_alpha, beta.ip_addresses[0]) as ping:
            await testing.wait_long(ping.wait_for_next_ping())

        wg_server = config.WG_SERVER

        await testing.wait_long(
            client_alpha.connect_to_vpn(
                wg_server["ipv4"],
                wg_server["port"],
                wg_server["public_key"],
            )
        )
        await testing.wait_lengthy(
            client_alpha.handshake(wg_server["public_key"], PathType.Direct)
        )

        async with Ping(connection_alpha, beta.ip_addresses[0]) as ping:
            await testing.wait_long(ping.wait_for_next_ping())

        async with Ping(connection_alpha, config.STUN_SERVER) as ping:
            await testing.wait_long(ping.wait_for_next_ping())

        public_ip = await testing.wait_long(
            stun.get(connection_alpha, config.STUN_SERVER)
        )
        assert (
            public_ip == wg_server["ipv4"]
        ), f"wrong public IP when connected to VPN {public_ip}"


@pytest.mark.asyncio
@pytest.mark.vpn
@pytest.mark.parametrize(
    "alpha_connection_tag,adapter_type",
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
    ],
)
async def test_mesh_plus_vpn_both_peers(
    alpha_connection_tag: ConnectionTag, adapter_type: AdapterType
) -> None:
    async with AsyncExitStack() as exit_stack:
        api = API()

        alpha = api.register(
            name="alpha",
            id="96ddb926-4b86-11ec-81d3-0242ac130003",
            private_key="IGm+42FLMMGZRaQvk6F3UPbl+T/CBk8W+NPoX2/AdlU=",
            public_key="41CCEssnYIh8/8D8YvbTfWEcFanG3D0I0z1tRcN1Lyc=",
        )

        beta = api.register(
            name="beta",
            id="7b4548ca-fe5a-4597-8513-896f38c6d6ae",
            private_key="SPFD84gPtBNc3iGY9Cdrj+mSCwBeh3mCMWfPaeWQolw=",
            public_key="Q1M3VKUcfTmGsrRzY6BpNds1yDIUvPVcs/2TySv/t1U=",
        )

        api.assign_ip(alpha.id, "100.64.33.2")
        api.assign_ip(beta.id, "100.64.33.3")

        beta.set_peer_firewall_settings(alpha.id, allow_incoming_connections=True)
        alpha.set_peer_firewall_settings(beta.id, allow_incoming_connections=True)

        connection_alpha = await exit_stack.enter_async_context(
            new_connection_by_tag(alpha_connection_tag)
        )
        connection_beta = await exit_stack.enter_async_context(
            new_connection_by_tag(ConnectionTag.DOCKER_CONE_CLIENT_2)
        )

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
                connection_beta,
                beta,
                api.get_meshmap(beta.id),
            )
        )

        await testing.wait_long(client_alpha.handshake(beta.public_key))
        await testing.wait_long(client_beta.handshake(alpha.public_key))

        async with Ping(connection_alpha, beta.ip_addresses[0]) as ping:
            await testing.wait_long(ping.wait_for_next_ping())

        wg_server = config.WG_SERVER

        await testing.wait_long(
            client_alpha.connect_to_vpn(
                wg_server["ipv4"],
                wg_server["port"],
                wg_server["public_key"],
            )
        )

        await testing.wait_long(
            client_beta.connect_to_vpn(
                wg_server["ipv4"],
                wg_server["port"],
                wg_server["public_key"],
            )
        )

        await testing.wait_lengthy(
            client_alpha.handshake(wg_server["public_key"], PathType.Direct)
        )
        await testing.wait_lengthy(
            client_beta.handshake(wg_server["public_key"], PathType.Direct)
        )

        async with Ping(connection_alpha, beta.ip_addresses[0]) as ping:
            await testing.wait_long(ping.wait_for_next_ping())
        async with Ping(connection_alpha, config.STUN_SERVER) as ping:
            await testing.wait_long(ping.wait_for_next_ping())

        async with Ping(connection_beta, alpha.ip_addresses[0]) as ping:
            await testing.wait_long(ping.wait_for_next_ping())
        async with Ping(connection_beta, config.STUN_SERVER) as ping:
            await testing.wait_long(ping.wait_for_next_ping())

        public_ip = await testing.wait_long(
            stun.get(connection_alpha, config.STUN_SERVER)
        )
        assert (
            public_ip == wg_server["ipv4"]
        ), f"wrong public IP when connected to VPN {public_ip}"

        public_ip = await testing.wait_long(
            stun.get(connection_beta, config.STUN_SERVER)
        )
        assert (
            public_ip == wg_server["ipv4"]
        ), f"wrong public IP when connected to VPN {public_ip}"


@pytest.mark.asyncio
@pytest.mark.vpn
@pytest.mark.parametrize(
    "alpha_connection_tag,adapter_type,public_ip",
    [
        pytest.param(
            ConnectionTag.DOCKER_CONE_CLIENT_1,
            AdapterType.BoringTun,
            "10.0.254.1",
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
        # pytest.param(
        #     ConnectionTag.MAC_VM,
        #     AdapterType.Default,
        #     "10.0.254.7",
        #     marks=pytest.mark.mac,
        # ),
    ],
)
async def test_vpn_plus_mesh(
    alpha_connection_tag: ConnectionTag, adapter_type: AdapterType, public_ip: str
) -> None:
    async with AsyncExitStack() as exit_stack:
        api = API()

        alpha = api.register(
            name="alpha",
            id="96ddb926-4b86-11ec-81d3-0242ac130003",
            private_key="IGm+42FLMMGZRaQvk6F3UPbl+T/CBk8W+NPoX2/AdlU=",
            public_key="41CCEssnYIh8/8D8YvbTfWEcFanG3D0I0z1tRcN1Lyc=",
        )

        beta = api.register(
            name="beta",
            id="7b4548ca-fe5a-4597-8513-896f38c6d6ae",
            private_key="SPFD84gPtBNc3iGY9Cdrj+mSCwBeh3mCMWfPaeWQolw=",
            public_key="Q1M3VKUcfTmGsrRzY6BpNds1yDIUvPVcs/2TySv/t1U=",
        )

        api.assign_ip(alpha.id, "100.64.33.2")
        api.assign_ip(beta.id, "100.64.33.3")

        beta.set_peer_firewall_settings(alpha.id, allow_incoming_connections=True)

        connection_alpha = await exit_stack.enter_async_context(
            new_connection_by_tag(alpha_connection_tag)
        )
        connection_beta = await exit_stack.enter_async_context(
            new_connection_by_tag(ConnectionTag.DOCKER_CONE_CLIENT_2)
        )

        ip = await testing.wait_long(stun.get(connection_alpha, config.STUN_SERVER))
        assert ip == public_ip, f"wrong public IP before connecting to VPN {ip}"

        client_alpha = await exit_stack.enter_async_context(
            telio.run(
                connection_alpha,
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

        async with Ping(connection_alpha, "10.0.80.80") as ping:
            await testing.wait_long(ping.wait_for_next_ping())

        ip = await testing.wait_long(stun.get(connection_alpha, config.STUN_SERVER))
        assert ip == wg_server["ipv4"], f"wrong public IP when connected to VPN {ip}"

        await client_alpha.set_meshmap(api.get_meshmap(alpha.id))

        client_beta = await exit_stack.enter_async_context(
            telio.run_meshnet(
                connection_beta,
                beta,
                api.get_meshmap(beta.id),
            )
        )

        await testing.wait_long(client_alpha.handshake(beta.public_key))
        await testing.wait_long(client_beta.handshake(alpha.public_key))

        async with Ping(connection_alpha, beta.ip_addresses[0]) as ping:
            await testing.wait_long(ping.wait_for_next_ping())


@pytest.mark.asyncio
@pytest.mark.vpn
@pytest.mark.timeout(150)
@pytest.mark.parametrize(
    "alpha_connection_tag,adapter_type",
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
    ],
)
async def test_vpn_plus_mesh_over_direct(
    alpha_connection_tag: ConnectionTag, adapter_type: AdapterType
) -> None:
    async with AsyncExitStack() as exit_stack:
        DERP_IP = str(DERP_PRIMARY["ipv4"])

        api = API()
        alpha = api.register(
            name="alpha",
            id="96ddb926-4b86-11ec-81d3-0242ac130003",
            private_key="IGm+42FLMMGZRaQvk6F3UPbl+T/CBk8W+NPoX2/AdlU=",
            public_key="41CCEssnYIh8/8D8YvbTfWEcFanG3D0I0z1tRcN1Lyc=",
        )

        beta = api.register(
            name="beta",
            id="7b4548ca-fe5a-4597-8513-896f38c6d6ae",
            private_key="SPFD84gPtBNc3iGY9Cdrj+mSCwBeh3mCMWfPaeWQolw=",
            public_key="Q1M3VKUcfTmGsrRzY6BpNds1yDIUvPVcs/2TySv/t1U=",
        )

        api.assign_ip(alpha.id, "100.64.33.2")
        api.assign_ip(beta.id, "100.64.33.3")

        alpha.set_peer_firewall_settings(beta.id, allow_incoming_connections=True)
        beta.set_peer_firewall_settings(alpha.id, allow_incoming_connections=True)

        connection_alpha = await exit_stack.enter_async_context(
            new_connection_by_tag(alpha_connection_tag)
        )
        connection_beta = await exit_stack.enter_async_context(
            new_connection_by_tag(ConnectionTag.DOCKER_CONE_CLIENT_2)
        )

        client_alpha = await exit_stack.enter_async_context(
            telio.run_meshnet(
                connection_alpha,
                alpha,
                api.get_meshmap(alpha.id),
                adapter_type,
                telio_features=TelioFeatures(
                    direct=Direct(providers=["local", "stun"])
                ),
            )
        )

        client_beta = await exit_stack.enter_async_context(
            telio.run_meshnet(
                connection_beta,
                beta,
                api.get_meshmap(beta.id),
                AdapterType.Default,
                telio_features=TelioFeatures(
                    direct=Direct(providers=["local", "stun"])
                ),
            )
        )

        await testing.wait_lengthy(
            asyncio.gather(
                client_alpha.wait_for_any_derp_state([telio.State.Connected]),
                client_beta.wait_for_any_derp_state([telio.State.Connected]),
            )
        )

        await testing.wait_defined(
            client_alpha.handshake(beta.public_key, PathType.Direct),
            80,
        )
        await testing.wait_lengthy(
            client_beta.handshake(alpha.public_key, PathType.Direct)
        )

        async with Ping(connection_alpha, beta.ip_addresses[0]) as ping:
            await testing.wait_lengthy(ping.wait_for_next_ping())

        wg_server = config.WG_SERVER

        await testing.wait_long(
            client_alpha.connect_to_vpn(
                wg_server["ipv4"],
                wg_server["port"],
                wg_server["public_key"],
            )
        )
        await testing.wait_lengthy(
            client_alpha.handshake(wg_server["public_key"], PathType.Direct)
        )

        await testing.wait_long(
            client_beta.connect_to_vpn(
                wg_server["ipv4"],
                wg_server["port"],
                wg_server["public_key"],
            )
        )
        await testing.wait_lengthy(
            client_beta.handshake(wg_server["public_key"], PathType.Direct)
        )

        async with Ping(connection_alpha, beta.ip_addresses[0]) as ping:
            await testing.wait_long(ping.wait_for_next_ping())
        async with Ping(connection_alpha, config.STUN_SERVER) as ping:
            await testing.wait_long(ping.wait_for_next_ping())

        async with Ping(connection_beta, alpha.ip_addresses[0]) as ping:
            await testing.wait_long(ping.wait_for_next_ping())
        async with Ping(connection_beta, config.STUN_SERVER) as ping:
            await testing.wait_long(ping.wait_for_next_ping())

        public_ip = await testing.wait_long(
            stun.get(connection_alpha, config.STUN_SERVER)
        )
        assert (
            public_ip == wg_server["ipv4"]
        ), f"wrong public IP when connected to VPN {public_ip}"

        public_ip = await testing.wait_long(
            stun.get(connection_beta, config.STUN_SERVER)
        )
        assert (
            public_ip == wg_server["ipv4"]
        ), f"wrong public IP when connected to VPN {public_ip}"


@pytest.mark.asyncio
@pytest.mark.vpn
@pytest.mark.timeout(150)
@pytest.mark.parametrize(
    "alpha_connection_tag,adapter_type",
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
    ],
)
async def test_vpn_plus_mesh_over_different_connection_types(
    alpha_connection_tag: ConnectionTag, adapter_type: AdapterType
) -> None:
    async with AsyncExitStack() as exit_stack:
        DERP_IP = str(DERP_PRIMARY["ipv4"])

        api = API()
        alpha = api.register(
            name="alpha",
            id="96ddb926-4b86-11ec-81d3-0242ac130003",
            private_key="IGm+42FLMMGZRaQvk6F3UPbl+T/CBk8W+NPoX2/AdlU=",
            public_key="41CCEssnYIh8/8D8YvbTfWEcFanG3D0I0z1tRcN1Lyc=",
        )

        beta = api.register(
            name="beta",
            id="7b4548ca-fe5a-4597-8513-896f38c6d6ae",
            private_key="SPFD84gPtBNc3iGY9Cdrj+mSCwBeh3mCMWfPaeWQolw=",
            public_key="Q1M3VKUcfTmGsrRzY6BpNds1yDIUvPVcs/2TySv/t1U=",
        )
        gamma = api.register(
            name="gamma",
            id="6b825055-91fa-41b7-ac65-78dbf397a2cd",
            private_key="CIDMCmjr6XSIZp6hnogYSlTYJNeFJmXgf28f27HKCXw=",
            public_key="655Gn59wY0AbzIvUfQPFSCJkQOhrg6gszlxeVKPIlgw=",
        )

        api.assign_ip(alpha.id, "100.64.33.2")
        api.assign_ip(beta.id, "100.64.33.3")
        api.assign_ip(gamma.id, "100.64.33.4")

        alpha.set_peer_firewall_settings(beta.id, allow_incoming_connections=True)
        alpha.set_peer_firewall_settings(gamma.id, allow_incoming_connections=True)
        beta.set_peer_firewall_settings(alpha.id, allow_incoming_connections=True)
        beta.set_peer_firewall_settings(gamma.id, allow_incoming_connections=True)
        gamma.set_peer_firewall_settings(alpha.id, allow_incoming_connections=True)
        gamma.set_peer_firewall_settings(beta.id, allow_incoming_connections=True)

        connection_alpha = await exit_stack.enter_async_context(
            new_connection_by_tag(alpha_connection_tag)
        )
        connection_beta = await exit_stack.enter_async_context(
            new_connection_by_tag(ConnectionTag.DOCKER_CONE_CLIENT_2)
        )
        connection_gamma = await exit_stack.enter_async_context(
            new_connection_by_tag(ConnectionTag.DOCKER_SYMMETRIC_CLIENT_1)
        )

        client_alpha = await exit_stack.enter_async_context(
            telio.run_meshnet(
                connection_alpha,
                alpha,
                api.get_meshmap(alpha.id),
                adapter_type,
                telio_features=TelioFeatures(
                    direct=Direct(providers=["local", "stun"])
                ),
            )
        )

        client_beta = await exit_stack.enter_async_context(
            telio.run_meshnet(
                connection_beta,
                beta,
                api.get_meshmap(beta.id),
                AdapterType.Default,
                telio_features=TelioFeatures(
                    direct=Direct(providers=["local", "stun"])
                ),
            )
        )

        client_gamma = await exit_stack.enter_async_context(
            telio.run_meshnet(
                connection_gamma,
                gamma,
                api.get_meshmap(gamma.id),
            )
        )

        await testing.wait_long(client_alpha.handshake(gamma.public_key))
        await testing.wait_long(client_gamma.handshake(alpha.public_key))

        await testing.wait_lengthy(
            asyncio.gather(
                client_alpha.wait_for_any_derp_state([telio.State.Connected]),
                client_beta.wait_for_any_derp_state([telio.State.Connected]),
                client_beta.wait_for_any_derp_state([telio.State.Connected]),
            )
        )

        await testing.wait_defined(
            client_alpha.handshake(beta.public_key, PathType.Direct),
            80,
        )
        await testing.wait_lengthy(
            client_beta.handshake(alpha.public_key, PathType.Direct)
        )
        await testing.wait_lengthy(client_alpha.handshake(gamma.public_key))

        async with Ping(connection_alpha, beta.ip_addresses[0]) as ping:
            await testing.wait_lengthy(ping.wait_for_next_ping())
        async with Ping(connection_alpha, gamma.ip_addresses[0]) as ping:
            await testing.wait_lengthy(ping.wait_for_next_ping())

        wg_server = config.WG_SERVER

        await testing.wait_long(
            client_alpha.connect_to_vpn(
                wg_server["ipv4"],
                wg_server["port"],
                wg_server["public_key"],
            )
        )
        await testing.wait_lengthy(
            client_alpha.handshake(wg_server["public_key"], PathType.Direct)
        )

        await testing.wait_long(
            client_beta.connect_to_vpn(
                wg_server["ipv4"],
                wg_server["port"],
                wg_server["public_key"],
            )
        )
        await testing.wait_lengthy(
            client_beta.handshake(wg_server["public_key"], PathType.Direct)
        )

        await testing.wait_long(
            client_gamma.connect_to_vpn(
                wg_server["ipv4"],
                wg_server["port"],
                wg_server["public_key"],
            )
        )
        await testing.wait_lengthy(
            client_gamma.handshake(wg_server["public_key"], PathType.Direct)
        )

        async with Ping(connection_alpha, beta.ip_addresses[0]) as ping:
            await testing.wait_long(ping.wait_for_next_ping())
        async with Ping(connection_alpha, gamma.ip_addresses[0]) as ping:
            await testing.wait_long(ping.wait_for_next_ping())
        async with Ping(connection_alpha, config.STUN_SERVER) as ping:
            await testing.wait_long(ping.wait_for_next_ping())

        async with Ping(connection_beta, alpha.ip_addresses[0]) as ping:
            await testing.wait_long(ping.wait_for_next_ping())
        async with Ping(connection_beta, config.STUN_SERVER) as ping:
            await testing.wait_long(ping.wait_for_next_ping())

        async with Ping(connection_gamma, alpha.ip_addresses[0]) as ping:
            await testing.wait_long(ping.wait_for_next_ping())
        async with Ping(connection_gamma, config.STUN_SERVER) as ping:
            await testing.wait_long(ping.wait_for_next_ping())

        public_ip = await testing.wait_long(
            stun.get(connection_alpha, config.STUN_SERVER)
        )
        assert (
            public_ip == wg_server["ipv4"]
        ), f"wrong public IP when connected to VPN {public_ip}"

        public_ip = await testing.wait_long(
            stun.get(connection_beta, config.STUN_SERVER)
        )
        assert (
            public_ip == wg_server["ipv4"]
        ), f"wrong public IP when connected to VPN {public_ip}"

        public_ip = await testing.wait_long(
            stun.get(connection_gamma, config.STUN_SERVER)
        )
        assert (
            public_ip == wg_server["ipv4"]
        ), f"wrong public IP when connected to VPN {public_ip}"
