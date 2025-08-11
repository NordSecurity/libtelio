# pylint: disable=too-many-lines

import asyncio
import config
import json
import pytest
import urllib
from contextlib import AsyncExitStack
from helpers import SetupParameters, setup_environment, setup_connections
from telio import Client
from typing import Optional, Tuple
from uniffi import FirewallBlacklistTuple, IpProtocol
from utils import testing, stun
from utils.bindings import (
    default_features,
    PathType,
    NodeState,
    TelioAdapterType,
    VpnConnectionError,
    generate_secret_key,
    generate_public_key,
)
from utils.connection import Connection, ConnectionTag
from utils.connection_tracker import (
    ConnectionTracker,
    TCPStateSequence as ConnTrackerTCPStateSequence,
    FiveTuple,
    TcpState,
)
from utils.connection_util import generate_connection_tracker_config
from utils.netcat import NetCatClient
from utils.ping import ping
from utils.process import ProcessExecError
from utils.python import get_python_binary
from utils.router import IPProto, IPStack

VAGRANT_LIBVIRT_MANAGEMENT_IP = "192.168.121"


async def _connect_vpn(
    client_conn: Connection,
    vpn_connection: Optional[Connection],
    client: Client,
    client_meshnet_ip: str,
    wg_server: dict,
) -> None:
    await client.connect_to_vpn(
        wg_server["ipv4"], wg_server["port"], wg_server["public_key"]
    )

    await ping(client_conn, config.PHOTO_ALBUM_IP)

    if vpn_connection is not None:
        await ping(vpn_connection, client_meshnet_ip)

    ip = await stun.get(client_conn, config.STUN_SERVER)
    assert ip == wg_server["ipv4"], f"wrong public IP when connected to VPN {ip}"


async def ensure_interface_router_property_expectations(client_conn: Connection):
    process = await client_conn.create_process([
        get_python_binary(client_conn),
        f"{config.LIBTELIO_BINARY_PATH_VM_MAC}/list_interfaces_with_router_property.py",
    ]).execute()
    interfaces_with_router_prop = process.get_stdout().splitlines()
    assert len(interfaces_with_router_prop) == 1
    assert VAGRANT_LIBVIRT_MANAGEMENT_IP in interfaces_with_router_prop[0]


class VpnConfig:
    # pinging the client is not a requirement and requires routing setup which might not be present
    def __init__(
        self,
        server_conf,
        conn_tag: ConnectionTag,
        should_ping_client: bool,
    ):
        self.server_conf = server_conf
        self.conn_tag = conn_tag
        self.should_ping_client = should_ping_client

    def __repr__(self) -> str:
        return (
            f"VpnConfig(server_conf={self.server_conf}, conn_tag={self.conn_tag},"
            f" should_ping_client={self.should_ping_client})"
        )


@pytest.mark.parametrize(
    "alpha_setup_params, public_ip",
    [
        pytest.param(
            SetupParameters(
                connection_tag=ConnectionTag.DOCKER_CONE_CLIENT_1,
                adapter_type_override=TelioAdapterType.NEP_TUN,
                is_meshnet=False,
            ),
            "10.0.254.1",
        ),
        pytest.param(
            SetupParameters(
                connection_tag=ConnectionTag.DOCKER_CONE_CLIENT_1,
                adapter_type_override=TelioAdapterType.LINUX_NATIVE_TUN,
                is_meshnet=False,
            ),
            "10.0.254.1",
            marks=pytest.mark.linux_native,
        ),
        pytest.param(
            SetupParameters(
                connection_tag=ConnectionTag.VM_WINDOWS_1,
                adapter_type_override=TelioAdapterType.WINDOWS_NATIVE_TUN,
                is_meshnet=False,
            ),
            "10.0.254.7",
            marks=[
                pytest.mark.windows,
            ],
        ),
        pytest.param(
            SetupParameters(
                connection_tag=ConnectionTag.VM_MAC,
                adapter_type_override=TelioAdapterType.NEP_TUN,
                is_meshnet=False,
            ),
            "10.0.254.7",
            marks=pytest.mark.mac,
        ),
    ],
)
@pytest.mark.parametrize(
    "vpn_conf",
    [
        pytest.param(
            VpnConfig(config.WG_SERVER, ConnectionTag.DOCKER_VPN_1, True),
            id="wg_server",
        ),
        pytest.param(
            VpnConfig(config.NLX_SERVER, ConnectionTag.DOCKER_NLX_1, False),
            id="nlx_server",
        ),
    ],
)
async def test_vpn_connection(
    alpha_setup_params: SetupParameters,
    vpn_conf: VpnConfig,
    public_ip: str,
) -> None:
    async with AsyncExitStack() as exit_stack:
        alpha_setup_params.connection_tracker_config = (
            generate_connection_tracker_config(
                alpha_setup_params.connection_tag,
                stun_limits=(1, 1),
                nlx_1_limits=(
                    (1, 1)
                    if vpn_conf.conn_tag == ConnectionTag.DOCKER_NLX_1
                    else (0, 0)
                ),
                vpn_1_limits=(
                    (1, 1)
                    if vpn_conf.conn_tag == ConnectionTag.DOCKER_VPN_1
                    else (0, 0)
                ),
            )
        )
        env = await exit_stack.enter_async_context(
            setup_environment(exit_stack, [alpha_setup_params], prepare_vpn=True)
        )

        alpha, *_ = env.nodes
        client_conn, *_ = [conn.connection for conn in env.connections]
        client_alpha, *_ = env.clients

        if alpha_setup_params.connection_tag == ConnectionTag.VM_MAC:
            await ensure_interface_router_property_expectations(client_conn)

        ip = await stun.get(client_conn, config.STUN_SERVER)
        assert ip == public_ip, f"wrong public IP before connecting to VPN {ip}"

        if vpn_conf.should_ping_client:
            vpn_connection, *_ = await setup_connections(
                exit_stack, [vpn_conf.conn_tag]
            )
            await _connect_vpn(
                client_conn,
                vpn_connection.connection,
                client_alpha,
                alpha.ip_addresses[0],
                vpn_conf.server_conf,
            )
        else:
            await _connect_vpn(
                client_conn,
                None,
                client_alpha,
                alpha.ip_addresses[0],
                vpn_conf.server_conf,
            )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "alpha_setup_params, public_ip",
    [
        pytest.param(
            SetupParameters(
                connection_tag=ConnectionTag.DOCKER_CONE_CLIENT_1,
                adapter_type_override=TelioAdapterType.NEP_TUN,
                connection_tracker_config=generate_connection_tracker_config(
                    ConnectionTag.DOCKER_CONE_CLIENT_1,
                    vpn_1_limits=(1, 1),
                    vpn_2_limits=(1, 1),
                    stun_limits=(1, 2),
                ),
                is_meshnet=False,
            ),
            "10.0.254.1",
        ),
        pytest.param(
            SetupParameters(
                connection_tag=ConnectionTag.DOCKER_CONE_CLIENT_1,
                adapter_type_override=TelioAdapterType.LINUX_NATIVE_TUN,
                connection_tracker_config=generate_connection_tracker_config(
                    ConnectionTag.DOCKER_CONE_CLIENT_1,
                    vpn_1_limits=(1, 1),
                    vpn_2_limits=(1, 1),
                    stun_limits=(1, 2),
                ),
                is_meshnet=False,
            ),
            "10.0.254.1",
            marks=pytest.mark.linux_native,
        ),
        pytest.param(
            SetupParameters(
                connection_tag=ConnectionTag.VM_WINDOWS_1,
                adapter_type_override=TelioAdapterType.WINDOWS_NATIVE_TUN,
                connection_tracker_config=generate_connection_tracker_config(
                    ConnectionTag.VM_WINDOWS_1,
                    vpn_1_limits=(1, 1),
                    vpn_2_limits=(1, 1),
                    stun_limits=(1, 2),
                ),
                is_meshnet=False,
            ),
            "10.0.254.7",
            marks=[
                pytest.mark.windows,
            ],
        ),
        pytest.param(
            SetupParameters(
                connection_tag=ConnectionTag.VM_MAC,
                adapter_type_override=TelioAdapterType.NEP_TUN,
                connection_tracker_config=generate_connection_tracker_config(
                    ConnectionTag.VM_MAC,
                    vpn_1_limits=(1, 1),
                    vpn_2_limits=(1, 1),
                    stun_limits=(1, 2),
                ),
                is_meshnet=False,
            ),
            "10.0.254.7",
            marks=pytest.mark.mac,
        ),
    ],
)
async def test_vpn_reconnect(
    alpha_setup_params: SetupParameters, public_ip: str
) -> None:
    async with AsyncExitStack() as exit_stack:
        env = await exit_stack.enter_async_context(
            setup_environment(exit_stack, [alpha_setup_params], prepare_vpn=True)
        )

        alpha, *_ = env.nodes
        connection, *_ = [conn.connection for conn in env.connections]
        client_alpha, *_ = env.clients

        vpn_1_connection, vpn_2_connection = await setup_connections(
            exit_stack, [ConnectionTag.DOCKER_VPN_1, ConnectionTag.DOCKER_VPN_2]
        )

        ip = await stun.get(connection, config.STUN_SERVER)
        assert ip == public_ip, f"wrong public IP before connecting to VPN {ip}"

        await _connect_vpn(
            connection,
            vpn_1_connection.connection,
            client_alpha,
            alpha.ip_addresses[0],
            config.WG_SERVER,
        )

        await client_alpha.disconnect_from_vpn(str(config.WG_SERVER["public_key"]))

        ip = await stun.get(connection, config.STUN_SERVER)
        assert ip == public_ip, f"wrong public IP before connecting to VPN {ip}"

        await _connect_vpn(
            connection,
            vpn_2_connection.connection,
            client_alpha,
            alpha.ip_addresses[0],
            config.WG_SERVER_2,
        )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "setup_params",
    [
        # IPv4 public server
        pytest.param(
            SetupParameters(
                connection_tag=ConnectionTag.DOCKER_CONE_CLIENT_1,
                adapter_type_override=TelioAdapterType.NEP_TUN,
                ip_stack=IPStack.IPv4,
                features=default_features(
                    enable_firewall_connection_reset=True,
                    enable_firewall_exclusion_range="10.0.0.0/8",
                ),
            )
        ),
        pytest.param(
            SetupParameters(
                connection_tag=ConnectionTag.DOCKER_CONE_CLIENT_1,
                adapter_type_override=TelioAdapterType.NEP_TUN,
                ip_stack=IPStack.IPv6,
                features=default_features(
                    enable_firewall_connection_reset=True,
                    enable_firewall_exclusion_range="10.0.0.0/8",
                ),
            )
        ),
    ],
)
async def test_kill_external_tcp_conn_on_vpn_reconnect(
    setup_params: SetupParameters,
) -> None:
    serv_ip = (
        config.PHOTO_ALBUM_IPV6
        if setup_params.ip_stack == IPStack.IPv6
        else config.PHOTO_ALBUM_IP
    )

    async with AsyncExitStack() as exit_stack:
        env = await exit_stack.enter_async_context(
            setup_environment(exit_stack, [setup_params], prepare_vpn=True)
        )

        alpha, *_ = env.nodes
        connection, *_ = [conn.connection for conn in env.connections]
        client, *_ = env.clients

        async def connect(
            wg_server: dict,
        ):
            await client.connect_to_vpn(
                wg_server["ipv4"], wg_server["port"], wg_server["public_key"]
            )

            await ping(connection, serv_ip)

        await connect(
            config.WG_SERVER,
        )

        async with ConnectionTracker(
            connection,
            [
                ConnTrackerTCPStateSequence(
                    "telio-kill-connection",
                    FiveTuple(protocol="tcp", dst_ip=serv_ip, dst_port=80),
                    [TcpState.CLOSE],
                )
            ],
        ).run() as conntrack:
            ip_proto = (
                IPProto.IPv6 if setup_params.ip_stack == IPStack.IPv6 else IPProto.IPv4
            )
            alpha_ip = testing.unpack_optional(alpha.get_ip_address(ip_proto))

            nc_client_1 = await exit_stack.enter_async_context(
                NetCatClient(
                    connection,
                    serv_ip,
                    80,
                    ipv6=ip_proto == IPProto.IPv6,
                    source_ip=alpha_ip,
                ).run()
            )

            # Second client, this time sending some data to check proper TCP sequence number generation
            nc_client_2 = await exit_stack.enter_async_context(
                NetCatClient(
                    connection,
                    serv_ip,
                    80,
                    ipv6=ip_proto == IPProto.IPv6,
                    source_ip=alpha_ip,
                ).run()
            )

            # Wait for both netcat processes
            await asyncio.gather(
                nc_client_1.connection_succeeded(), nc_client_2.connection_succeeded()
            )

            # exchange some data
            await nc_client_2.send_data("GET")

            # the key is generated uniquely each time natlab runs
            await client.disconnect_from_vpn(str(config.WG_SERVER["public_key"]))

            await connect(
                config.WG_SERVER_2,
            )

            # under normal circumstances -> conntrack should show FIN_WAIT -> CLOSE_WAIT
            # But our connection killing mechanism will reset connection resulting in CLOSE output.
            # Wait for close on both clients
            await conntrack.wait_for_no_violations()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "ipv4",
    [
        pytest.param(True),
        pytest.param(False),
    ],
)
async def test_firewall_blacklist_tcp(ipv4: bool) -> None:
    serv_ip = config.PHOTO_ALBUM_IP if ipv4 else config.PHOTO_ALBUM_IPV6
    serv_port = 80
    wg_server: dict = config.WG_SERVER

    setup_params = [
        SetupParameters(
            connection_tag=ConnectionTag.DOCKER_CONE_CLIENT_1,
            adapter_type_override=TelioAdapterType.NEP_TUN,
            ip_stack=IPStack.IPv4 if ipv4 else IPStack.IPv6,
        ),
        SetupParameters(
            connection_tag=ConnectionTag.DOCKER_CONE_CLIENT_2,
            adapter_type_override=TelioAdapterType.NEP_TUN,
            ip_stack=IPStack.IPv4 if ipv4 else IPStack.IPv6,
        ),
    ]

    setup_params[1].features.firewall.outgoing_blacklist = [
        FirewallBlacklistTuple(protocol=IpProtocol.TCP, ip=serv_ip, port=serv_port)
    ]

    async with AsyncExitStack() as exit_stack:
        env = await exit_stack.enter_async_context(
            setup_environment(exit_stack, setup_params, prepare_vpn=True)
        )

        alpha_connection, beta_connection, *_ = [
            conn.connection for conn in env.connections
        ]
        alpha, beta, *_ = env.clients

        await alpha.connect_to_vpn(
            wg_server["ipv4"], wg_server["port"], wg_server["public_key"]
        )

        await beta.connect_to_vpn(
            wg_server["ipv4"], wg_server["port"], wg_server["public_key"]
        )

        async with ConnectionTracker(
            alpha_connection,
            [
                ConnTrackerTCPStateSequence(
                    "telio-kill-blacklisted-connection",
                    FiveTuple(protocol="tcp", dst_ip=serv_ip, dst_port=serv_port),
                    [TcpState.FIN_WAIT, TcpState.LAST_ACK, TcpState.TIME_WAIT],
                    trailing_state=TcpState.CLOSE,
                )
            ],
        ).run() as conntrack:
            serv_ip = serv_ip if ipv4 else "[" + serv_ip + "]"
            await alpha_connection.create_process(["curl", serv_ip]).execute()
            await conntrack.wait_for_no_violations()

        async with ConnectionTracker(
            beta_connection,
            [
                ConnTrackerTCPStateSequence(
                    "telio-kill-blacklisted-connection",
                    FiveTuple(protocol="tcp", dst_ip=serv_ip, dst_port=serv_port),
                    [TcpState.SYN_SENT, TcpState.CLOSE],
                )
            ],
        ).run() as conntrack:

            with pytest.raises(ProcessExecError):
                await beta_connection.create_process(["curl", serv_ip]).execute()

            await conntrack.wait_for_no_violations()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "ipv4",
    [
        pytest.param(True),
        pytest.param(False),
    ],
)
async def test_firewall_blacklist_udp(ipv4: bool) -> None:
    serv_ip = config.UDP_SERVER_IP4 if ipv4 else config.UDP_SERVER_IP6
    serv_port = 2000
    wg_server: dict = config.WG_SERVER

    setup_params = [
        SetupParameters(
            connection_tag=ConnectionTag.DOCKER_CONE_CLIENT_1,
            adapter_type_override=TelioAdapterType.NEP_TUN,
            ip_stack=IPStack.IPv4 if ipv4 else IPStack.IPv6,
        ),
        SetupParameters(
            connection_tag=ConnectionTag.DOCKER_CONE_CLIENT_2,
            adapter_type_override=TelioAdapterType.NEP_TUN,
            ip_stack=IPStack.IPv4 if ipv4 else IPStack.IPv6,
        ),
    ]

    setup_params[1].features.firewall.outgoing_blacklist = [
        FirewallBlacklistTuple(protocol=IpProtocol.UDP, ip=serv_ip, port=serv_port)
    ]

    async with AsyncExitStack() as exit_stack:
        env = await exit_stack.enter_async_context(
            setup_environment(exit_stack, setup_params, prepare_vpn=True)
        )

        alpha, beta, *_ = env.nodes
        alpha_connection, beta_connection, *_ = [
            conn.connection for conn in env.connections
        ]
        alpha_client, beta_client, *_ = env.clients

        await alpha_client.connect_to_vpn(
            wg_server["ipv4"], wg_server["port"], wg_server["public_key"]
        )

        await beta_client.connect_to_vpn(
            wg_server["ipv4"], wg_server["port"], wg_server["public_key"]
        )

        alpha_nc_client = await exit_stack.enter_async_context(
            NetCatClient(
                alpha_connection,
                serv_ip,
                serv_port,
                udp=True,
                source_ip=testing.unpack_optional(
                    alpha.get_ip_address(IPProto.IPv4 if ipv4 else IPProto.IPv6)
                ),
                ipv6=not ipv4,
            ).run()
        )
        await alpha_nc_client.connection_succeeded()

        with pytest.raises(ProcessExecError):
            await NetCatClient(
                beta_connection,
                serv_ip,
                serv_port,
                udp=True,
                source_ip=testing.unpack_optional(
                    beta.get_ip_address(IPProto.IPv4 if ipv4 else IPProto.IPv6)
                ),
                ipv6=not ipv4,
            ).execute()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "setup_params",
    [
        # IPv4 public server
        pytest.param(
            SetupParameters(
                connection_tag=ConnectionTag.DOCKER_CONE_CLIENT_1,
                adapter_type_override=TelioAdapterType.NEP_TUN,
                ip_stack=IPStack.IPv4,
                features=default_features(
                    enable_firewall_connection_reset=True,
                    enable_firewall_exclusion_range="10.0.0.0/8",
                ),
            )
        ),
        pytest.param(
            SetupParameters(
                connection_tag=ConnectionTag.VM_MAC,
                adapter_type_override=TelioAdapterType.NEP_TUN,
                ip_stack=IPStack.IPv4,
                features=default_features(
                    enable_firewall_connection_reset=True,
                    enable_firewall_exclusion_range="10.0.0.0/8",
                ),
            ),
            marks=pytest.mark.mac,
        ),
        pytest.param(
            SetupParameters(
                connection_tag=ConnectionTag.DOCKER_OPEN_INTERNET_CLIENT_DUAL_STACK,
                adapter_type_override=TelioAdapterType.NEP_TUN,
                ip_stack=IPStack.IPv6,
                features=default_features(enable_firewall_connection_reset=True),
            )
        ),
    ],
)
async def test_kill_external_udp_conn_on_vpn_reconnect(
    setup_params: SetupParameters,
) -> None:
    serv_ip = (
        config.UDP_SERVER_IP6
        if setup_params.ip_stack == IPStack.IPv6
        else config.UDP_SERVER_IP4
    )

    async with AsyncExitStack() as exit_stack:
        env = await exit_stack.enter_async_context(
            setup_environment(exit_stack, [setup_params], prepare_vpn=True)
        )

        alpha, *_ = env.nodes
        connection, *_ = [conn.connection for conn in env.connections]
        client, *_ = env.clients

        async def connect(
            wg_server: dict,
        ):
            await client.connect_to_vpn(
                wg_server["ipv4"], wg_server["port"], wg_server["public_key"]
            )

            await ping(connection, serv_ip)

        await connect(
            config.WG_SERVER,
        )

        ip_proto = (
            IPProto.IPv6 if setup_params.ip_stack == IPStack.IPv6 else IPProto.IPv4
        )
        alpha_ip = testing.unpack_optional(alpha.get_ip_address(ip_proto))

        nc_client = await exit_stack.enter_async_context(
            NetCatClient(
                connection,
                serv_ip,
                2000,
                udp=True,
                ipv6=ip_proto == IPProto.IPv6,
                source_ip=alpha_ip,
            ).run()
        )

        await nc_client.connection_succeeded()
        await client.disconnect_from_vpn(str(config.WG_SERVER["public_key"]))

        await connect(
            config.WG_SERVER_2,
        )

        # nc client should be closed by the reset mechanism
        await nc_client.is_done()


@pytest.mark.parametrize(
    "alpha_setup_params, public_ip",
    [
        pytest.param(
            SetupParameters(
                connection_tag=ConnectionTag.DOCKER_CONE_CLIENT_1,
                adapter_type_override=TelioAdapterType.NEP_TUN,
                connection_tracker_config=generate_connection_tracker_config(
                    ConnectionTag.DOCKER_CONE_CLIENT_1,
                    stun_limits=(1, 1),
                    vpn_1_limits=(1, 1),
                ),
                is_meshnet=False,
            ),
            "10.0.254.1",
        ),
        pytest.param(
            SetupParameters(
                connection_tag=ConnectionTag.DOCKER_CONE_CLIENT_1,
                adapter_type_override=TelioAdapterType.LINUX_NATIVE_TUN,
                connection_tracker_config=generate_connection_tracker_config(
                    ConnectionTag.DOCKER_CONE_CLIENT_1,
                    stun_limits=(1, 1),
                    vpn_1_limits=(1, 1),
                ),
                is_meshnet=False,
            ),
            "10.0.254.1",
            marks=pytest.mark.linux_native,
        ),
        pytest.param(
            SetupParameters(
                connection_tag=ConnectionTag.VM_WINDOWS_1,
                adapter_type_override=TelioAdapterType.WINDOWS_NATIVE_TUN,
                connection_tracker_config=generate_connection_tracker_config(
                    ConnectionTag.VM_WINDOWS_1,
                    stun_limits=(1, 1),
                    vpn_1_limits=(1, 1),
                ),
                is_meshnet=False,
            ),
            "10.0.254.7",
            marks=[
                pytest.mark.windows,
            ],
        ),
        pytest.param(
            SetupParameters(
                connection_tag=ConnectionTag.VM_MAC,
                adapter_type_override=TelioAdapterType.NEP_TUN,
                connection_tracker_config=generate_connection_tracker_config(
                    ConnectionTag.VM_MAC,
                    stun_limits=(1, 1),
                    vpn_1_limits=(1, 1),
                ),
                is_meshnet=False,
            ),
            "10.0.254.7",
            marks=pytest.mark.mac,
        ),
    ],
)
async def test_vpn_connection_private_key_change(
    alpha_setup_params: SetupParameters,
    public_ip: str,
) -> None:
    async with AsyncExitStack() as exit_stack:
        env = await exit_stack.enter_async_context(
            setup_environment(exit_stack, [alpha_setup_params], prepare_vpn=True)
        )

        alpha, *_ = env.nodes
        client_conn, *_ = [conn.connection for conn in env.connections]
        client_alpha, *_ = env.clients

        ip = await asyncio.wait_for(stun.get(client_conn, config.STUN_SERVER), 5)
        assert ip == public_ip, f"wrong public IP before connecting to VPN {ip}"

        # connect to vpn as usually
        vpn_connection, *_ = await setup_connections(
            exit_stack, [ConnectionTag.DOCKER_VPN_1]
        )
        await _connect_vpn(
            client_conn,
            vpn_connection.connection,
            client_alpha,
            alpha.ip_addresses[0],
            config.WG_SERVER,
        )

        new_secret_key = generate_secret_key()
        new_public_key = generate_public_key(new_secret_key)

        # change public key on server
        await vpn_connection.connection.create_process(
            ["./opt/bin/update_wg_peer_key", alpha.public_key, new_public_key]
        ).execute()

        # change key
        await client_alpha.set_secret_key(new_secret_key)

        # ping again
        await ping(client_conn, config.PHOTO_ALBUM_IP, 5)

        ip = await stun.get(client_conn, config.STUN_SERVER)
        assert (
            ip == config.WG_SERVER["ipv4"]
        ), f"wrong public IP when connected to VPN {ip}"


@pytest.mark.parametrize(
    "alpha_setup_params, public_ip",
    [
        pytest.param(
            SetupParameters(
                connection_tag=ConnectionTag.DOCKER_CONE_CLIENT_1,
                adapter_type_override=TelioAdapterType.NEP_TUN,
                is_meshnet=False,
                features=default_features(
                    enable_error_notification_service=True,
                ),
            ),
            "10.0.254.1",
        ),
        pytest.param(
            SetupParameters(
                connection_tag=ConnectionTag.DOCKER_CONE_CLIENT_1,
                adapter_type_override=TelioAdapterType.LINUX_NATIVE_TUN,
                is_meshnet=False,
                features=default_features(
                    enable_error_notification_service=True,
                ),
            ),
            "10.0.254.1",
            marks=pytest.mark.linux_native,
        ),
        pytest.param(
            SetupParameters(
                connection_tag=ConnectionTag.VM_WINDOWS_1,
                adapter_type_override=TelioAdapterType.WINDOWS_NATIVE_TUN,
                is_meshnet=False,
                features=default_features(
                    enable_error_notification_service=True,
                ),
            ),
            "10.0.254.7",
            marks=[
                pytest.mark.windows,
            ],
        ),
        pytest.param(
            SetupParameters(
                connection_tag=ConnectionTag.VM_MAC,
                adapter_type_override=TelioAdapterType.NEP_TUN,
                is_meshnet=False,
                features=default_features(
                    enable_error_notification_service=True,
                ),
            ),
            "10.0.254.7",
            marks=pytest.mark.mac,
        ),
    ],
)
@pytest.mark.parametrize(
    "error_code",
    [
        (0, VpnConnectionError.UNKNOWN),
        (1, VpnConnectionError.CONNECTION_LIMIT_REACHED),
        (2, VpnConnectionError.SERVER_MAINTENANCE),
        (3, VpnConnectionError.UNAUTHENTICATED),
        (4, VpnConnectionError.SUPERSEDED),
        (5, VpnConnectionError.UNKNOWN),
    ],
)
async def test_ens(
    alpha_setup_params: SetupParameters,
    public_ip: str,
    error_code: Tuple[int, VpnConnectionError],
) -> None:
    vpn_conf = VpnConfig(config.WG_SERVER, ConnectionTag.DOCKER_VPN_1, True)
    async with AsyncExitStack() as exit_stack:

        await set_vpn_server_private_key(
            vpn_conf.server_conf["ipv4"],
            vpn_conf.server_conf["private_key"],
        )

        alpha_setup_params.connection_tracker_config = (
            generate_connection_tracker_config(
                alpha_setup_params.connection_tag,
                stun_limits=(1, 1),
                vpn_1_limits=(
                    (1, 1)
                    if vpn_conf.conn_tag == ConnectionTag.DOCKER_VPN_1
                    else (0, 0)
                ),
            )
        )
        env = await exit_stack.enter_async_context(
            setup_environment(exit_stack, [alpha_setup_params], prepare_vpn=True)
        )

        client_conn, *_ = [conn.connection for conn in env.connections]
        client_alpha, *_ = env.clients

        if alpha_setup_params.connection_tag == ConnectionTag.VM_MAC:
            await ensure_interface_router_property_expectations(client_conn)

        ip = await stun.get(client_conn, config.STUN_SERVER)
        assert ip == public_ip, f"wrong public IP before connecting to VPN {ip}"

        await setup_connections(exit_stack, [vpn_conf.conn_tag])

        await client_alpha.connect_to_vpn(
            vpn_conf.server_conf["ipv4"],
            vpn_conf.server_conf["port"],
            vpn_conf.server_conf["public_key"],
        )

        additional_info = "some additional info"
        await trigger_connection_error(
            vpn_conf.server_conf["ipv4"], error_code[0], additional_info
        )
        await client_alpha.wait_for_state_peer(
            vpn_conf.server_conf["public_key"],
            [NodeState.CONNECTED],
            [PathType.DIRECT],
            True,
            True,
            vpn_connection_error=error_code[1],
        )
        await client_alpha.wait_for_log(additional_info)


async def trigger_connection_error(vpn_ip, error_code, additional_info):
    data = {"code": error_code, "additional_info": additional_info}
    url = f"http://{vpn_ip}:8000/api/connection_error"
    await make_request(url, data)


async def set_vpn_server_private_key(vpn_ip, vpn_server_private_key):
    data = {"vpn_server_private_key": vpn_server_private_key}
    url = f"http://{vpn_ip}:8000/api/vpn_server_private_key"
    await make_request(url, data)


async def make_request(url, data):
    def blocking_request():
        req = urllib.request.Request(
            url,
            data=json.dumps(data).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req) as response:
            return json.loads(response.read().decode("utf-8"))

    return await asyncio.to_thread(blocking_request)


@pytest.mark.parametrize(
    "alpha_setup_params, public_ip",
    [
        pytest.param(
            SetupParameters(
                connection_tag=ConnectionTag.DOCKER_CONE_CLIENT_1,
                adapter_type_override=TelioAdapterType.NEP_TUN,
                is_meshnet=False,
                features=default_features(
                    enable_error_notification_service=True,
                ),
            ),
            "10.0.254.1",
        ),
        pytest.param(
            SetupParameters(
                connection_tag=ConnectionTag.DOCKER_CONE_CLIENT_1,
                adapter_type_override=TelioAdapterType.LINUX_NATIVE_TUN,
                is_meshnet=False,
                features=default_features(
                    enable_error_notification_service=True,
                ),
            ),
            "10.0.254.1",
            marks=pytest.mark.linux_native,
        ),
        pytest.param(
            SetupParameters(
                connection_tag=ConnectionTag.VM_WINDOWS_1,
                adapter_type_override=TelioAdapterType.WINDOWS_NATIVE_TUN,
                is_meshnet=False,
                features=default_features(
                    enable_error_notification_service=True,
                ),
            ),
            "10.0.254.7",
            marks=[
                pytest.mark.windows,
            ],
        ),
        pytest.param(
            SetupParameters(
                connection_tag=ConnectionTag.VM_MAC,
                adapter_type_override=TelioAdapterType.NEP_TUN,
                is_meshnet=False,
                features=default_features(
                    enable_error_notification_service=True,
                ),
            ),
            "10.0.254.7",
            marks=pytest.mark.mac,
        ),
    ],
)
async def test_ens_not_working(
    alpha_setup_params: SetupParameters,
    public_ip: str,
) -> None:
    vpn_conf = VpnConfig(config.WG_SERVER, ConnectionTag.DOCKER_VPN_1, True)
    async with AsyncExitStack() as exit_stack:
        await set_vpn_server_private_key(
            vpn_conf.server_conf["ipv4"],
            vpn_conf.server_conf["private_key"],
        )

        alpha_setup_params.connection_tracker_config = (
            generate_connection_tracker_config(
                alpha_setup_params.connection_tag,
                stun_limits=(1, 1),
                vpn_1_limits=(
                    (1, 1)
                    if vpn_conf.conn_tag == ConnectionTag.DOCKER_VPN_1
                    else (0, 0)
                ),
            )
        )
        env = await exit_stack.enter_async_context(
            setup_environment(exit_stack, [alpha_setup_params], prepare_vpn=True)
        )

        alpha, *_ = env.nodes
        client_conn, *_ = [conn.connection for conn in env.connections]
        client_alpha, *_ = env.clients

        if alpha_setup_params.connection_tag == ConnectionTag.VM_MAC:
            await ensure_interface_router_property_expectations(client_conn)

        ip = await stun.get(client_conn, config.STUN_SERVER)
        assert ip == public_ip, f"wrong public IP before connecting to VPN {ip}"

        vpn_connection, *_ = await setup_connections(exit_stack, [vpn_conf.conn_tag])
        await exit_stack.enter_async_context(
            client_alpha.get_router().block_tcp_port(993)
        )

        await _connect_vpn(
            client_conn,
            vpn_connection.connection,
            client_alpha,
            alpha.ip_addresses[0],
            vpn_conf.server_conf,
        )
