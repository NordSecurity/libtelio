import asyncio
import pytest
from tests import config
from tests.helpers import SetupParameters
from tests.helpers_vpn import connect_vpn, VpnConfig
from tests.uniffi import FeatureFirewall, FirewallBlacklistTuple, IpProtocol
from tests.utils import testing, stun
from tests.utils.bindings import (
    default_features,
    TelioAdapterType,
    generate_secret_key,
    generate_public_key,
)
from tests.utils.connection import ConnectionTag
from tests.utils.connection_tracker import (
    ConnectionTracker,
    TCPStateSequence as ConnTrackerTCPStateSequence,
    FiveTuple,
    TcpState,
)
from tests.utils.connection_util import generate_connection_tracker_config
from tests.utils.netcat import NetCatClient
from tests.utils.ping import ping
from tests.utils.process import ProcessExecError
from tests.utils.router import IPProto, IPStack

pytest_plugins = ["tests.helpers_fixtures"]


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
            marks=pytest.mark.nlx,
        ),
    ],
)
async def test_vpn_connection(
    alpha_setup_params: SetupParameters,  # pylint: disable=unused-argument
    vpn_conf: VpnConfig,
    public_ip: str,
    alpha_node,
    client_conn,
    client_alpha,
    vpn_server_connection,
) -> None:
    ip = await stun.get(client_conn, config.STUN_SERVER)
    assert ip == public_ip, f"wrong public IP before connecting to VPN {ip}"

    await connect_vpn(
        client_conn,
        vpn_server_connection.connection if vpn_server_connection is not None else None,
        client_alpha,
        alpha_node.ip_addresses[0],
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
    alpha_setup_params: SetupParameters,
    public_ip: str,
    setup_environment_factory,
    setup_connections_factory,
) -> None:
    env = await setup_environment_factory(
        [alpha_setup_params],
        vpn=[ConnectionTag.DOCKER_VPN_1, ConnectionTag.DOCKER_VPN_2],
    )

    alpha, *_ = env.nodes
    connection, *_ = [conn.connection for conn in env.connections]
    client_alpha, *_ = env.clients

    vpn_1_connection, vpn_2_connection = await setup_connections_factory(
        [ConnectionTag.DOCKER_VPN_1, ConnectionTag.DOCKER_VPN_2]
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
    setup_environment_factory,
) -> None:
    serv_ip = (
        config.PHOTO_ALBUM_IPV6
        if setup_params.ip_stack == IPStack.IPv6
        else config.PHOTO_ALBUM_IP
    )

    env = await setup_environment_factory(
        [setup_params],
        vpn=[ConnectionTag.DOCKER_VPN_1, ConnectionTag.DOCKER_VPN_2],
    )

    alpha, *_ = env.nodes
    connection, *_ = [conn.connection for conn in env.connections]
    client, *_ = env.clients

    async def connect(wg_server: dict):
        await client.connect_to_vpn(
            wg_server["ipv4"], wg_server["port"], wg_server["public_key"]
        )
        await ping(connection, serv_ip)

    await connect(config.WG_SERVER)

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
        alpha_ip: str = testing.unpack_optional(alpha.get_ip_address(ip_proto))

        async with NetCatClient(
            connection,
            serv_ip,
            80,
            ipv6=ip_proto == IPProto.IPv6,
            source_ip=alpha_ip,
        ).run() as nc_client_1:
            async with NetCatClient(
                connection,
                serv_ip,
                80,
                ipv6=ip_proto == IPProto.IPv6,
                source_ip=alpha_ip,
            ).run() as nc_client_2:
                await asyncio.gather(
                    nc_client_1.connection_succeeded(),
                    nc_client_2.connection_succeeded(),
                )

                await nc_client_2.send_data("GET")

                await client.disconnect_from_vpn(str(config.WG_SERVER["public_key"]))

                await connect(config.WG_SERVER_2)

                await conntrack.wait_for_no_violations()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "ipv4",
    [
        pytest.param(True),
        pytest.param(False),
    ],
)
async def test_firewall_blacklist_tcp(
    ipv4: bool,
    setup_environment_factory,
) -> None:
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

    setup_params[1].features.firewall = FeatureFirewall(
        neptun_reset_conns=False,
        boringtun_reset_conns=False,
        exclude_private_ip_range=None,
        outgoing_blacklist=[
            FirewallBlacklistTuple(protocol=IpProtocol.TCP, ip=serv_ip, port=serv_port)
        ],
    )

    env = await setup_environment_factory(
        setup_params, vpn=[ConnectionTag.DOCKER_VPN_1]
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
async def test_firewall_blacklist_udp(
    ipv4: bool,
    setup_environment_factory,
) -> None:
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

    setup_params[1].features.firewall = FeatureFirewall(
        neptun_reset_conns=False,
        boringtun_reset_conns=False,
        exclude_private_ip_range=None,
        outgoing_blacklist=[
            FirewallBlacklistTuple(protocol=IpProtocol.UDP, ip=serv_ip, port=serv_port)
        ],
    )

    env = await setup_environment_factory(
        setup_params, vpn=[ConnectionTag.DOCKER_VPN_1]
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

    async with NetCatClient(
        alpha_connection,
        serv_ip,
        serv_port,
        udp=True,
        source_ip=testing.unpack_optional(
            alpha.get_ip_address(IPProto.IPv4 if ipv4 else IPProto.IPv6)
        ),
        ipv6=not ipv4,
    ).run() as alpha_nc_client:
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
    setup_environment_factory,
) -> None:
    serv_ip = (
        config.UDP_SERVER_IP6
        if setup_params.ip_stack == IPStack.IPv6
        else config.UDP_SERVER_IP4
    )

    env = await setup_environment_factory(
        [setup_params],
        vpn=[ConnectionTag.DOCKER_VPN_1, ConnectionTag.DOCKER_VPN_2],
    )

    alpha, *_ = env.nodes
    connection, *_ = [conn.connection for conn in env.connections]
    client, *_ = env.clients

    async def connect(wg_server: dict):
        await client.connect_to_vpn(
            wg_server["ipv4"], wg_server["port"], wg_server["public_key"]
        )
        await ping(connection, serv_ip)

    await connect(config.WG_SERVER)

    ip_proto = IPProto.IPv6 if setup_params.ip_stack == IPStack.IPv6 else IPProto.IPv4
    alpha_ip: str = testing.unpack_optional(alpha.get_ip_address(ip_proto))

    async with NetCatClient(
        connection,
        serv_ip,
        2000,
        udp=True,
        ipv6=ip_proto == IPProto.IPv6,
        source_ip=alpha_ip,
    ).run() as nc_client:
        await nc_client.connection_succeeded()
        await client.disconnect_from_vpn(str(config.WG_SERVER["public_key"]))

        await connect(config.WG_SERVER_2)

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
    setup_environment_factory,
    setup_connections_factory,
) -> None:
    env = await setup_environment_factory(
        [alpha_setup_params],
        vpn=[ConnectionTag.DOCKER_VPN_1],
    )

    alpha, *_ = env.nodes
    client_conn, *_ = [conn.connection for conn in env.connections]
    client_alpha, *_ = env.clients

    ip = await stun.get(client_conn, config.STUN_SERVER)
    assert ip == public_ip, f"wrong public IP before connecting to VPN {ip}"

    # connect to vpn as usually
    vpn_connection, *_ = await setup_connections_factory([ConnectionTag.DOCKER_VPN_1])
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
    assert ip == config.WG_SERVER["ipv4"], f"wrong public IP when connected to VPN {ip}"
