import asyncio
import config
import pytest
from contextlib import AsyncExitStack
from helpers import SetupParameters, setup_environment, setup_connections
from helpers_vpn import connect_vpn, VpnConfig
from uniffi import FirewallBlacklistTuple, IpProtocol
from utils import testing, stun
from utils.bindings import (
    default_features,
    TelioAdapterType,
    generate_secret_key,
    generate_public_key,
)
from utils.connection import ConnectionTag
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
from utils.router import IPProto, IPStack


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
            "10.0.254.15",
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
            "10.0.254.19",
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
            VpnConfig(config.NLX_SERVER, ConnectionTag.VM_LINUX_NLX_1, False),
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
                    if vpn_conf.conn_tag == ConnectionTag.VM_LINUX_NLX_1
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

        ip = await stun.get(client_conn, config.STUN_SERVER)
        assert ip == public_ip, f"wrong public IP before connecting to VPN {ip}"

        if vpn_conf.should_ping_client:
            vpn_connection, *_ = await setup_connections(
                exit_stack, [vpn_conf.conn_tag]
            )
            await connect_vpn(
                client_conn,
                vpn_connection.connection,
                client_alpha,
                alpha.ip_addresses[0],
                vpn_conf.server_conf,
            )
        else:
            await connect_vpn(
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
            "10.0.254.15",
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
            "10.0.254.19",
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

        await connect_vpn(
            connection,
            vpn_1_connection.connection,
            client_alpha,
            alpha.ip_addresses[0],
            config.WG_SERVER,
        )

        await client_alpha.disconnect_from_vpn(str(config.WG_SERVER["public_key"]))

        ip = await stun.get(connection, config.STUN_SERVER)
        assert ip == public_ip, f"wrong public IP before connecting to VPN {ip}"

        await connect_vpn(
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
            "10.0.254.15",
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
            "10.0.254.19",
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

        ip = await stun.get(client_conn, config.STUN_SERVER)
        assert ip == public_ip, f"wrong public IP before connecting to VPN {ip}"

        # connect to vpn as usually
        vpn_connection, *_ = await setup_connections(
            exit_stack, [ConnectionTag.DOCKER_VPN_1]
        )
        await connect_vpn(
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
