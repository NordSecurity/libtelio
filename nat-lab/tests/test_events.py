import asyncio
import config
import pytest
import telio
from contextlib import AsyncExitStack
from mesh_api import API
from telio import AdapterType, PathType, PeerInfo, State
from telio_features import TelioFeatures, Direct
from typing import List
from utils import testing, stun
from utils.connection_tracker import ConnectionLimits
from utils.connection_util import (
    generate_connection_tracker_config,
    ConnectionTag,
    new_connection_with_conn_tracker,
)
from utils.ping import Ping
from utils.router import IPProto, get_ip_address_type


def get_allowed_ip_list(addrs: List[str]) -> List[str]:
    ret: List[str] = []

    for ip in addrs:
        typ = get_ip_address_type(ip)

        if typ == IPProto.IPv4:
            ret.append(ip + "/32")
        elif typ == IPProto.IPv6:
            ret.append(ip + "/128")

    return ret


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
async def test_event_content_meshnet(
    alpha_connection_tag: ConnectionTag, adapter_type: AdapterType
) -> None:
    async with AsyncExitStack() as exit_stack:
        api = API()

        (alpha, beta) = api.default_config_two_nodes()
        (connection_alpha, alpha_conn_tracker) = await exit_stack.enter_async_context(
            new_connection_with_conn_tracker(
                alpha_connection_tag,
                generate_connection_tracker_config(
                    alpha_connection_tag, derp_1_limits=ConnectionLimits(1, 1)
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
            telio.Client(connection_alpha, alpha, adapter_type).run(
                api.get_meshmap(alpha.id)
            )
        )

        client_beta = await exit_stack.enter_async_context(
            telio.Client(connection_beta, beta).run(api.get_meshmap(beta.id))
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
        async with Ping(connection_beta, alpha.ip_addresses[0]).run() as ping:
            await testing.wait_long(ping.wait_for_next_ping())

        assert client_alpha.get_node_state(beta.public_key) == PeerInfo(
            identifier=beta.id,
            public_key=beta.public_key,
            state=State.Connected,
            is_exit=False,
            is_vpn=False,
            ip_addresses=beta.ip_addresses,
            allowed_ips=get_allowed_ip_list(beta.ip_addresses),
            nickname=None,
            endpoint=None,
            hostname=beta.name + ".nord",
            allow_incoming_connections=True,
            allow_peer_send_files=False,
            path=PathType.Relay,
        )

        assert client_beta.get_node_state(alpha.public_key) == PeerInfo(
            identifier=alpha.id,
            public_key=alpha.public_key,
            state=State.Connected,
            is_exit=False,
            is_vpn=False,
            ip_addresses=alpha.ip_addresses,
            allowed_ips=get_allowed_ip_list(alpha.ip_addresses),
            nickname=None,
            endpoint=None,
            hostname=alpha.name + ".nord",
            allow_incoming_connections=True,
            allow_peer_send_files=False,
            path=PathType.Relay,
        )

        api.remove(beta.id)

        await client_alpha.set_meshmap(api.get_meshmap(alpha.id))

        with pytest.raises(asyncio.TimeoutError):
            async with Ping(connection_alpha, beta.ip_addresses[0]).run() as ping:
                await testing.wait_normal(ping.wait_for_next_ping())

        await asyncio.sleep(1)

        assert client_alpha.get_node_state(beta.public_key) == PeerInfo(
            identifier=beta.id,
            public_key=beta.public_key,
            state=State.Disconnected,
            is_exit=False,
            is_vpn=False,
            ip_addresses=beta.ip_addresses,
            allowed_ips=get_allowed_ip_list(beta.ip_addresses),
            nickname=None,
            endpoint=None,
            hostname=beta.name + ".nord",
            allow_incoming_connections=True,
            allow_peer_send_files=False,
            path=PathType.Direct,
        )

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
async def test_event_content_vpn_connection(
    alpha_connection_tag: ConnectionTag, adapter_type: AdapterType, public_ip: str
) -> None:
    async with AsyncExitStack() as exit_stack:
        api = API()

        alpha = api.default_config_one_node()
        (connection, alpha_conn_tracker) = await exit_stack.enter_async_context(
            new_connection_with_conn_tracker(
                alpha_connection_tag,
                generate_connection_tracker_config(
                    alpha_connection_tag,
                    vpn_1_limits=ConnectionLimits(1, 1),
                    stun_limits=ConnectionLimits(2, 2),
                ),
            )
        )

        ip: str = await testing.wait_long(stun.get(connection, config.STUN_SERVER))
        await testing.wait_long(alpha_conn_tracker.wait_for_event("stun"))
        assert ip == public_ip, f"wrong public IP before connecting to VPN {ip}"

        client_alpha = await exit_stack.enter_async_context(
            telio.Client(connection, alpha, adapter_type).run()
        )

        wg_server = config.WG_SERVER

        await testing.wait_long(
            client_alpha.connect_to_vpn(
                wg_server["ipv4"], wg_server["port"], wg_server["public_key"]
            )
        )
        await testing.wait_long(alpha_conn_tracker.wait_for_event("vpn_1"))
        await testing.wait_lengthy(
            client_alpha.wait_for_state_peer(
                wg_server["public_key"], [State.Connected], [PathType.Direct]
            )
        )

        async with Ping(connection, config.PHOTO_ALBUM_IP).run() as ping:
            await testing.wait_long(ping.wait_for_next_ping())

        assert client_alpha.get_node_state(str(wg_server["public_key"])) == PeerInfo(
            identifier="tcli",
            public_key=str(wg_server["public_key"]),
            state=State.Connected,
            is_exit=True,
            is_vpn=True,
            ip_addresses=[
                "10.5.0.1",
                "100.64.0.1",
            ],
            allowed_ips=["0.0.0.0/0", "::/0"],
            nickname=None,
            endpoint=f'{wg_server["ipv4"]}:{wg_server["port"]}',
            hostname=None,
            allow_incoming_connections=False,
            allow_peer_send_files=False,
            path=PathType.Direct,
        )

        ip = await testing.wait_long(stun.get(connection, config.STUN_SERVER))
        assert ip == wg_server["ipv4"], f"wrong public IP when connected to VPN {ip}"

        await testing.wait_lengthy(
            client_alpha.disconnect_from_vpn(
                wg_server["public_key"], paths=[PathType.Direct]
            )
        )

        ip = await testing.wait_long(stun.get(connection, config.STUN_SERVER))
        await testing.wait_long(alpha_conn_tracker.wait_for_event("stun"))
        assert ip == public_ip, f"wrong public IP before connecting to VPN {ip}"

        await testing.wait_lengthy(
            client_alpha.wait_for_state_peer(
                str(wg_server["public_key"]),
                [telio.State.Disconnected],
                [PathType.Direct],
            )
        )

        assert client_alpha.get_node_state(str(wg_server["public_key"])) == PeerInfo(
            identifier="tcli",
            public_key=str(wg_server["public_key"]),
            state=State.Disconnected,
            is_exit=True,
            is_vpn=True,
            ip_addresses=[
                "10.5.0.1",
                "100.64.0.1",
            ],
            allowed_ips=["0.0.0.0/0", "::/0"],
            nickname=None,
            endpoint=f'{wg_server["ipv4"]}:{wg_server["port"]}',
            hostname=None,
            allow_incoming_connections=False,
            allow_peer_send_files=False,
            path=PathType.Direct,
        )

        assert alpha_conn_tracker.get_out_of_limits() is None


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "alpha_connection_tag,adapter_type",
    [
        pytest.param(ConnectionTag.DOCKER_CONE_CLIENT_1, telio.AdapterType.BoringTun),
        pytest.param(
            ConnectionTag.DOCKER_CONE_CLIENT_1,
            telio.AdapterType.LinuxNativeWg,
            marks=pytest.mark.linux_native,
        ),
        pytest.param(
            ConnectionTag.WINDOWS_VM,
            telio.AdapterType.WindowsNativeWg,
            marks=pytest.mark.windows,
        ),
        pytest.param(
            ConnectionTag.WINDOWS_VM,
            telio.AdapterType.WireguardGo,
            marks=pytest.mark.windows,
        ),
        pytest.param(
            ConnectionTag.MAC_VM, telio.AdapterType.Default, marks=pytest.mark.mac
        ),
    ],
)
async def test_event_content_exit_through_peer(
    alpha_connection_tag: ConnectionTag, adapter_type: AdapterType
) -> None:
    async with AsyncExitStack() as exit_stack:
        api = API()

        (alpha, beta) = api.default_config_two_nodes()
        alpha.set_peer_firewall_settings(beta.id, allow_incoming_connections=False)
        (connection_alpha, alpha_conn_tracker) = await exit_stack.enter_async_context(
            new_connection_with_conn_tracker(
                alpha_connection_tag,
                generate_connection_tracker_config(
                    alpha_connection_tag, derp_1_limits=ConnectionLimits(1, 1)
                ),
            )
        )
        (connection_beta, beta_conn_tracker) = await exit_stack.enter_async_context(
            new_connection_with_conn_tracker(
                ConnectionTag.DOCKER_CONE_CLIENT_2,
                generate_connection_tracker_config(
                    ConnectionTag.DOCKER_CONE_CLIENT_2,
                    derp_1_limits=ConnectionLimits(1, 1),
                    stun_limits=ConnectionLimits(2, 2),
                ),
            )
        )

        client_alpha = await exit_stack.enter_async_context(
            telio.Client(connection_alpha, alpha, adapter_type).run(
                api.get_meshmap(alpha.id)
            )
        )

        client_beta = await exit_stack.enter_async_context(
            telio.Client(connection_beta, beta).run(api.get_meshmap(beta.id))
        )

        await testing.wait_long(
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

        assert client_alpha.get_node_state(beta.public_key) == PeerInfo(
            identifier=beta.id,
            public_key=beta.public_key,
            state=State.Connected,
            is_exit=False,
            is_vpn=False,
            ip_addresses=beta.ip_addresses,
            allowed_ips=get_allowed_ip_list(beta.ip_addresses),
            nickname=None,
            endpoint=None,
            hostname=beta.name + ".nord",
            allow_incoming_connections=False,
            allow_peer_send_files=False,
            path=PathType.Relay,
        )

        await testing.wait_long(client_beta.get_router().create_exit_node_route())

        await testing.wait_long(
            asyncio.gather(
                client_alpha.connect_to_exit_node(beta.public_key),
                client_alpha.wait_for_event_peer(beta.public_key, [State.Connected]),
            )
        )

        ip_alpha: str = await testing.wait_long(
            stun.get(connection_alpha, config.STUN_SERVER)
        )
        await testing.wait_long(beta_conn_tracker.wait_for_event("stun"))
        ip_beta: str = await testing.wait_long(
            stun.get(connection_beta, config.STUN_SERVER)
        )
        await testing.wait_long(beta_conn_tracker.wait_for_event("stun"))

        assert ip_alpha == ip_beta

        assert client_alpha.get_node_state(beta.public_key) == PeerInfo(
            identifier=beta.id,
            public_key=beta.public_key,
            state=State.Connected,
            is_exit=True,
            is_vpn=False,
            ip_addresses=beta.ip_addresses,
            allowed_ips=["0.0.0.0/0", "::/0"],
            nickname=None,
            endpoint=None,
            hostname=beta.name + ".nord",
            allow_incoming_connections=False,
            allow_peer_send_files=False,
            path=PathType.Relay,
        )

        assert alpha_conn_tracker.get_out_of_limits() is None
        assert beta_conn_tracker.get_out_of_limits() is None


@pytest.mark.asyncio
@pytest.mark.timeout(90)
@pytest.mark.parametrize(
    "alpha_connection_tag,adapter_type,alpha_public_ip",
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
async def test_event_content_meshnet_node_upgrade_direct(
    alpha_connection_tag: ConnectionTag, adapter_type: AdapterType, alpha_public_ip: str
) -> None:
    async with AsyncExitStack() as exit_stack:
        api = API()
        beta_public_ip = "10.0.254.2"

        (alpha, beta) = api.default_config_two_nodes()
        (connection_alpha, alpha_conn_tracker) = await exit_stack.enter_async_context(
            new_connection_with_conn_tracker(
                alpha_connection_tag,
                generate_connection_tracker_config(
                    alpha_connection_tag, derp_1_limits=ConnectionLimits(1, 1)
                ),
            )
        )
        (connection_beta, beta_conn_tracker) = await exit_stack.enter_async_context(
            new_connection_with_conn_tracker(
                ConnectionTag.DOCKER_CONE_CLIENT_2,
                generate_connection_tracker_config(
                    ConnectionTag.DOCKER_CONE_CLIENT_2,
                    derp_1_limits=ConnectionLimits(2, 2),
                ),
            )
        )

        client_alpha = await exit_stack.enter_async_context(
            telio.Client(
                connection_alpha,
                alpha,
                adapter_type,
                telio_features=TelioFeatures(direct=Direct(providers=["stun"])),
            ).run(api.get_meshmap(alpha.id))
        )

        client_beta = await exit_stack.enter_async_context(
            telio.Client(connection_beta, beta).run(api.get_meshmap(beta.id))
        )

        await testing.wait_long(
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
        async with Ping(connection_beta, alpha.ip_addresses[0]).run() as ping:
            await testing.wait_long(ping.wait_for_next_ping())

        beta_node_state = client_alpha.get_node_state(beta.public_key)
        assert beta_node_state
        assert beta_node_state == PeerInfo(
            identifier=beta.id,
            public_key=beta.public_key,
            state=State.Connected,
            is_exit=False,
            is_vpn=False,
            ip_addresses=beta.ip_addresses,
            allowed_ips=get_allowed_ip_list(beta.ip_addresses),
            nickname=None,
            endpoint=None,
            hostname=beta.name + ".nord",
            allow_incoming_connections=True,
            allow_peer_send_files=False,
            path=PathType.Relay,
        )
        assert (
            beta_node_state.endpoint and beta_public_ip not in beta_node_state.endpoint
        )

        alpha_node_state = client_beta.get_node_state(alpha.public_key)
        assert alpha_node_state
        assert alpha_node_state == PeerInfo(
            identifier=alpha.id,
            public_key=alpha.public_key,
            state=State.Connected,
            is_exit=False,
            is_vpn=False,
            ip_addresses=alpha.ip_addresses,
            allowed_ips=get_allowed_ip_list(alpha.ip_addresses),
            nickname=None,
            endpoint=None,
            hostname=alpha.name + ".nord",
            allow_incoming_connections=True,
            allow_peer_send_files=False,
            path=PathType.Relay,
        )
        assert (
            alpha_node_state.endpoint
            and alpha_public_ip not in alpha_node_state.endpoint
        )

        await client_beta.stop_device()
        del client_beta

        client_beta = await exit_stack.enter_async_context(
            telio.Client(
                connection_beta,
                beta,
                telio_features=TelioFeatures(direct=Direct(providers=["stun"])),
            ).run(api.get_meshmap(beta.id))
        )

        await testing.wait_lengthy(
            client_beta.wait_for_state_on_any_derp([State.Connected])
        )

        await testing.wait_long(beta_conn_tracker.wait_for_event("derp_1"))

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
            await testing.wait_long(ping.wait_for_next_ping())
        async with Ping(connection_beta, alpha.ip_addresses[0]).run() as ping:
            await testing.wait_long(ping.wait_for_next_ping())

        beta_node_state = client_alpha.get_node_state(beta.public_key)
        assert beta_node_state
        assert beta_node_state == PeerInfo(
            identifier=beta.id,
            public_key=beta.public_key,
            state=State.Connected,
            is_exit=False,
            is_vpn=False,
            ip_addresses=beta.ip_addresses,
            allowed_ips=get_allowed_ip_list(beta.ip_addresses),
            nickname=None,
            endpoint=None,
            hostname=beta.name + ".nord",
            allow_incoming_connections=True,
            allow_peer_send_files=False,
            path=PathType.Direct,
        )
        assert beta_node_state.endpoint and beta_public_ip in beta_node_state.endpoint

        alpha_node_state = client_beta.get_node_state(alpha.public_key)
        assert alpha_node_state
        assert alpha_node_state == PeerInfo(
            identifier=alpha.id,
            public_key=alpha.public_key,
            state=State.Connected,
            is_exit=False,
            is_vpn=False,
            ip_addresses=alpha.ip_addresses,
            allowed_ips=get_allowed_ip_list(alpha.ip_addresses),
            nickname=None,
            endpoint=None,
            hostname=alpha.name + ".nord",
            allow_incoming_connections=True,
            allow_peer_send_files=False,
            path=PathType.Direct,
        )
        assert (
            alpha_node_state.endpoint and alpha_public_ip in alpha_node_state.endpoint
        )

        assert alpha_conn_tracker.get_out_of_limits() is None
        assert beta_conn_tracker.get_out_of_limits() is None
