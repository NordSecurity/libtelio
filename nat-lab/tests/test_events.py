from utils import Ping, stun
from contextlib import AsyncExitStack
from mesh_api import API
from telio import AdapterType, PathType
from telio_features import TelioFeatures, Direct
from utils import ConnectionTag, new_connection_by_tag
import asyncio
import pytest
import telio
import utils.testing as testing
import config


@pytest.mark.asyncio
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
        pytest.param(
            ConnectionTag.MAC_VM,
            AdapterType.Default,
            marks=pytest.mark.mac,
        ),
    ],
)
async def test_event_content_meshnet(
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

        api.assign_ip(alpha.id, "100.64.0.1")
        api.assign_ip(beta.id, "100.64.0.2")

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
            )
        )

        assert client_alpha.get_node_state(beta.public_key) is None

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
        async with Ping(connection_beta, alpha.ip_addresses[0]) as ping:
            await testing.wait_long(ping.wait_for_next_ping())

        node_state_beta_on_alpha_side = client_alpha.get_node_state(beta.public_key)
        assert node_state_beta_on_alpha_side is not None
        if node_state_beta_on_alpha_side:
            assert node_state_beta_on_alpha_side.is_exit == False
            assert node_state_beta_on_alpha_side.state == telio.State.Connected
            assert node_state_beta_on_alpha_side.is_vpn == False
            assert node_state_beta_on_alpha_side.endpoint
            assert node_state_beta_on_alpha_side.ip_addresses[0] == beta.ip_addresses[0]
            assert (
                beta.ip_addresses[0] + "/32"
                in node_state_beta_on_alpha_side.allowed_ips
            )
            assert node_state_beta_on_alpha_side.allow_incoming_connections
            assert node_state_beta_on_alpha_side.path == PathType.Relay

        node_state_alpha_on_beta_side = client_beta.get_node_state(alpha.public_key)
        assert node_state_alpha_on_beta_side is not None
        if node_state_alpha_on_beta_side:
            assert node_state_alpha_on_beta_side.is_exit == False
            assert node_state_alpha_on_beta_side.state == telio.State.Connected
            assert node_state_alpha_on_beta_side.is_vpn == False
            assert node_state_alpha_on_beta_side.endpoint
            assert (
                node_state_alpha_on_beta_side.ip_addresses[0] == alpha.ip_addresses[0]
            )
            assert (
                alpha.ip_addresses[0] + "/32"
                in node_state_alpha_on_beta_side.allowed_ips
            )
            assert node_state_alpha_on_beta_side.allow_incoming_connections
            assert node_state_alpha_on_beta_side.path == PathType.Relay

        api.remove(beta.id)

        await client_alpha.set_meshmap(api.get_meshmap(alpha.id))

        with pytest.raises(asyncio.TimeoutError):
            async with Ping(connection_alpha, beta.ip_addresses[0]) as ping:
                await testing.wait_normal(ping.wait_for_next_ping())

        await asyncio.sleep(1)

        node_state_beta_on_alpha_side = client_alpha.get_node_state(beta.public_key)
        assert node_state_beta_on_alpha_side is not None
        if node_state_beta_on_alpha_side:
            assert node_state_beta_on_alpha_side.is_exit == False
            assert node_state_beta_on_alpha_side.state == telio.State.Disconnected
            assert node_state_beta_on_alpha_side.is_vpn == False
            assert node_state_beta_on_alpha_side.endpoint
            assert node_state_beta_on_alpha_side.ip_addresses[0] == beta.ip_addresses[0]
            assert (
                beta.ip_addresses[0] + "/32"
                in node_state_beta_on_alpha_side.allowed_ips
            )
            assert node_state_beta_on_alpha_side.allow_incoming_connections
            assert node_state_beta_on_alpha_side.path == PathType.Direct


@pytest.mark.asyncio
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
        pytest.param(
            ConnectionTag.MAC_VM,
            AdapterType.Default,
            "10.0.254.7",
            marks=pytest.mark.mac,
        ),
    ],
)
async def test_event_content_vpn_connection(
    alpha_connection_tag: ConnectionTag, adapter_type: AdapterType, public_ip: str
) -> None:
    async with AsyncExitStack() as exit_stack:
        api = API()

        alpha = api.register(
            name="alpha",
            id="96ddb926-4b86-11ec-81d3-0242ac130003",
            private_key="yIsV88+fJrRJRKyMnbK7fHCAXWzaPeAuBILeJMtfQHI=",
            public_key="Oxm/ZeHev8trOJ69sRyvX1rngZc2Gq7sXxQq4MW7bW4=",
        )
        api.assign_ip(alpha.id, "100.64.33.1")

        connection = await exit_stack.enter_async_context(
            new_connection_by_tag(alpha_connection_tag)
        )

        ip: str = await testing.wait_long(stun.get(connection, config.STUN_SERVER))
        assert ip == public_ip, f"wrong public IP before connecting to VPN {ip}"

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
            client_alpha.handshake(wg_server["public_key"], path=PathType.Direct)
        )

        async with Ping(connection, "10.0.80.80") as ping:
            await testing.wait_long(ping.wait_for_next_ping())

        alpha_node_state = client_alpha.get_node_state(str(wg_server["public_key"]))
        assert alpha_node_state is not None
        if alpha_node_state:
            assert alpha_node_state.is_exit == True
            assert alpha_node_state.state == telio.State.Connected
            assert alpha_node_state.is_vpn == True
            assert alpha_node_state.endpoint == str(wg_server["ipv4"]) + ":" + str(
                wg_server["port"]
            )
            assert alpha_node_state.ip_addresses == ["10.5.0.1", "100.64.0.1"]
            assert "0.0.0.0/0" in alpha_node_state.allowed_ips
            assert alpha_node_state.allow_incoming_connections == False
            assert alpha_node_state.path == PathType.Direct

        ip = await testing.wait_long(stun.get(connection, config.STUN_SERVER))
        assert ip == wg_server["ipv4"], f"wrong public IP when connected to VPN {ip}"

        await testing.wait_lengthy(
            client_alpha.disconnect_from_vpn(
                wg_server["public_key"], path=PathType.Direct
            )
        )

        ip = await testing.wait_long(stun.get(connection, config.STUN_SERVER))
        assert ip == public_ip, f"wrong public IP before connecting to VPN {ip}"

        await asyncio.sleep(1)

        alpha_node_state = client_alpha.get_node_state(str(wg_server["public_key"]))
        assert alpha_node_state is not None
        if alpha_node_state:
            assert alpha_node_state.is_exit == True
            assert alpha_node_state.state == telio.State.Disconnected
            assert alpha_node_state.is_vpn == True
            assert alpha_node_state.endpoint == str(wg_server["ipv4"]) + ":" + str(
                wg_server["port"]
            )
            assert "0.0.0.0/0" in alpha_node_state.allowed_ips
            assert alpha_node_state.allow_incoming_connections == False
            assert alpha_node_state.path == PathType.Direct


@pytest.mark.asyncio
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
        pytest.param(
            ConnectionTag.MAC_VM,
            AdapterType.Default,
            marks=pytest.mark.mac,
        ),
    ],
)
async def test_event_content_exit_through_peer(
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

        api.assign_ip(alpha.id, "100.64.0.1")
        api.assign_ip(beta.id, "100.64.0.2")

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

        await asyncio.sleep(1)

        node_state_beta_on_alpha_side = client_alpha.get_node_state(beta.public_key)
        assert node_state_beta_on_alpha_side is not None
        if node_state_beta_on_alpha_side:
            assert node_state_beta_on_alpha_side.is_exit == False
            assert node_state_beta_on_alpha_side.state == telio.State.Connected
            assert node_state_beta_on_alpha_side.is_vpn == False
            assert node_state_beta_on_alpha_side.endpoint
            assert (
                beta.ip_addresses[0] + "/32"
                in node_state_beta_on_alpha_side.allowed_ips
            )
            assert node_state_beta_on_alpha_side.allow_incoming_connections == False
            assert node_state_beta_on_alpha_side.path == PathType.Relay

        await testing.wait_long(client_beta.get_router().create_exit_node_route())

        await testing.wait_long(
            client_alpha.connect_to_exit_node(
                beta.public_key,
            )
        )

        await testing.wait_long(client_alpha.handshake(beta.public_key))
        ip_alpha: str = await testing.wait_long(
            stun.get(connection_alpha, config.STUN_SERVER)
        )
        ip_beta: str = await testing.wait_long(
            stun.get(connection_beta, config.STUN_SERVER)
        )

        assert ip_alpha == ip_beta

        await asyncio.sleep(1)

        node_state_beta_on_alpha_side = client_alpha.get_node_state(beta.public_key)
        assert node_state_beta_on_alpha_side is not None
        if node_state_beta_on_alpha_side:
            assert node_state_beta_on_alpha_side.is_exit == True
            assert node_state_beta_on_alpha_side.state == telio.State.Connected
            assert node_state_beta_on_alpha_side.is_vpn == False
            assert node_state_beta_on_alpha_side.endpoint
            assert ["0.0.0.0/0"] == node_state_beta_on_alpha_side.allowed_ips
            assert node_state_beta_on_alpha_side.allow_incoming_connections == False
            assert node_state_beta_on_alpha_side.path == PathType.Relay


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "alpha_connection_tag,adapter_type,alpha_public_ip",
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
        pytest.param(
            ConnectionTag.MAC_VM,
            AdapterType.Default,
            "10.0.254.7",
            marks=pytest.mark.mac,
        ),
    ],
)
async def test_event_content_meshnet_node_upgrade_direct(
    alpha_connection_tag: ConnectionTag, adapter_type: AdapterType, alpha_public_ip: str
) -> None:
    async with AsyncExitStack() as exit_stack:
        api = API()
        beta_public_ip = "10.0.254.2"

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

        api.assign_ip(alpha.id, "100.64.0.1")
        api.assign_ip(beta.id, "100.64.0.2")

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
                telio_features=TelioFeatures(direct=Direct(providers=["stun"])),
            )
        )

        assert client_alpha.get_node_state(beta.public_key) is None

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
        async with Ping(connection_beta, alpha.ip_addresses[0]) as ping:
            await testing.wait_long(ping.wait_for_next_ping())

        await asyncio.sleep(1)

        node_state_beta_on_alpha_side = client_alpha.get_node_state(beta.public_key)
        assert node_state_beta_on_alpha_side is not None
        if node_state_beta_on_alpha_side:
            assert node_state_beta_on_alpha_side.is_exit == False
            assert node_state_beta_on_alpha_side.state == telio.State.Connected
            assert node_state_beta_on_alpha_side.is_vpn == False
            assert node_state_beta_on_alpha_side.endpoint
            assert beta_public_ip not in node_state_beta_on_alpha_side.endpoint
            assert (
                beta.ip_addresses[0] + "/32"
                in node_state_beta_on_alpha_side.allowed_ips
            )
            assert node_state_beta_on_alpha_side.allow_incoming_connections
            assert node_state_beta_on_alpha_side.path == PathType.Relay

        node_state_alpha_on_beta_side = client_beta.get_node_state(alpha.public_key)
        assert node_state_alpha_on_beta_side is not None
        if node_state_alpha_on_beta_side:
            assert node_state_alpha_on_beta_side.is_exit == False
            assert node_state_alpha_on_beta_side.state == telio.State.Connected
            assert node_state_alpha_on_beta_side.is_vpn == False
            assert node_state_alpha_on_beta_side.endpoint
            assert alpha_public_ip not in node_state_alpha_on_beta_side.endpoint
            assert (
                alpha.ip_addresses[0] + "/32"
                in node_state_alpha_on_beta_side.allowed_ips
            )
            assert node_state_alpha_on_beta_side.allow_incoming_connections
            assert node_state_alpha_on_beta_side.path == PathType.Relay

        await client_beta.stop_device()

        client_beta = await exit_stack.enter_async_context(
            telio.run_meshnet(
                connection_beta,
                beta,
                api.get_meshmap(beta.id),
                telio_features=TelioFeatures(direct=Direct(providers=["stun"])),
            )
        )

        await testing.wait_lengthy(
            asyncio.gather(
                client_alpha.wait_for_any_derp_state([telio.State.Connected]),
                client_beta.wait_for_any_derp_state([telio.State.Connected]),
            )
        )

        await testing.wait_defined(
            asyncio.gather(
                client_alpha.handshake(beta.public_key, path=PathType.Direct),
                client_beta.handshake(alpha.public_key, path=PathType.Direct),
            ),
            60,
        )

        await asyncio.sleep(1)

        async with Ping(connection_alpha, beta.ip_addresses[0]) as ping:
            await testing.wait_long(ping.wait_for_next_ping())
        async with Ping(connection_beta, alpha.ip_addresses[0]) as ping:
            await testing.wait_long(ping.wait_for_next_ping())

        node_state_beta_on_alpha_side = client_alpha.get_node_state(beta.public_key)
        assert node_state_beta_on_alpha_side is not None
        if node_state_beta_on_alpha_side:
            assert node_state_beta_on_alpha_side.is_exit == False
            assert node_state_beta_on_alpha_side.state == telio.State.Connected
            assert node_state_beta_on_alpha_side.is_vpn == False
            assert node_state_beta_on_alpha_side.endpoint
            assert beta_public_ip in node_state_beta_on_alpha_side.endpoint
            assert (
                beta.ip_addresses[0] + "/32"
                in node_state_beta_on_alpha_side.allowed_ips
            )
            assert node_state_beta_on_alpha_side.allow_incoming_connections
            assert node_state_beta_on_alpha_side.path == PathType.Direct

        node_state_alpha_on_beta_side = client_beta.get_node_state(alpha.public_key)
        assert node_state_alpha_on_beta_side is not None
        if node_state_alpha_on_beta_side:
            assert node_state_alpha_on_beta_side.is_exit == False
            assert node_state_alpha_on_beta_side.state == telio.State.Connected
            assert node_state_alpha_on_beta_side.is_vpn == False
            assert node_state_alpha_on_beta_side.endpoint
            assert alpha_public_ip in node_state_alpha_on_beta_side.endpoint
            assert (
                alpha.ip_addresses[0] + "/32"
                in node_state_alpha_on_beta_side.allowed_ips
            )
            assert node_state_alpha_on_beta_side.allow_incoming_connections
            assert node_state_alpha_on_beta_side.path == PathType.Direct
