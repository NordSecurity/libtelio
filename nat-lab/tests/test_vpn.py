import asyncio
import config
import copy
import pytest
from contextlib import AsyncExitStack
from helpers import SetupParameters, setup_environment, setup_connections
from telio import Client
from typing import Optional
from utils import testing, stun
from utils.bindings import (
    default_features,
    TelioAdapterType,
    generate_secret_key,
    generate_public_key,
)
from utils.connection import Connection
from utils.connection_tracker import (
    ConnectionLimits,
    ConnectionTrackerConfig,
    ConnectionTracker,
    FiveTuple,
    TcpState,
)
from utils.connection_util import generate_connection_tracker_config, ConnectionTag
from utils.netcat import NetCatClient
from utils.ping import ping
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
                adapter_type_override=TelioAdapterType.BORING_TUN,
                connection_tracker_config=generate_connection_tracker_config(
                    ConnectionTag.DOCKER_CONE_CLIENT_1,
                    stun_limits=ConnectionLimits(1, 1),
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
                    stun_limits=ConnectionLimits(1, 1),
                ),
                is_meshnet=False,
            ),
            "10.0.254.1",
            marks=pytest.mark.linux_native,
        ),
        pytest.param(
            SetupParameters(
                connection_tag=ConnectionTag.WINDOWS_VM_1,
                adapter_type_override=TelioAdapterType.WINDOWS_NATIVE_TUN,
                connection_tracker_config=generate_connection_tracker_config(
                    ConnectionTag.WINDOWS_VM_1,
                    stun_limits=ConnectionLimits(1, 1),
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
                connection_tag=ConnectionTag.WINDOWS_VM_1,
                adapter_type_override=TelioAdapterType.WIREGUARD_GO_TUN,
                connection_tracker_config=generate_connection_tracker_config(
                    ConnectionTag.WINDOWS_VM_1,
                    stun_limits=ConnectionLimits(1, 1),
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
                connection_tag=ConnectionTag.MAC_VM,
                adapter_type_override=TelioAdapterType.BORING_TUN,
                connection_tracker_config=generate_connection_tracker_config(
                    ConnectionTag.MAC_VM,
                    stun_limits=ConnectionLimits(1, 1),
                ),
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
    def find_cfg_by_key(
        params: SetupParameters, key: str
    ) -> Optional[ConnectionTrackerConfig]:
        if params.connection_tracker_config is not None:
            for cfg in params.connection_tracker_config:
                if cfg.get_key() == key:
                    return cfg
        return None

    async with AsyncExitStack() as exit_stack:
        alpha_setup_params = copy.deepcopy(alpha_setup_params)

        if vpn_conf.conn_tag == ConnectionTag.DOCKER_VPN_1:
            cfg = find_cfg_by_key(alpha_setup_params, "vpn_1")
            assert cfg is not None
            cfg.limits = ConnectionLimits(1, 1)

        elif vpn_conf.conn_tag == ConnectionTag.DOCKER_NLX_1:
            cfg = find_cfg_by_key(alpha_setup_params, "nlx_1")
            assert cfg is not None
            cfg.limits = ConnectionLimits(1, 1)

        else:
            raise ValueError(f"Unknown connection tag {vpn_conf.conn_tag}")

        env = await exit_stack.enter_async_context(
            setup_environment(exit_stack, [alpha_setup_params])
        )

        alpha, *_ = env.nodes
        client_conn, *_ = [conn.connection for conn in env.connections]
        client_alpha, *_ = env.clients

        if alpha_setup_params.connection_tag == ConnectionTag.MAC_VM:
            process = await client_conn.create_process([
                get_python_binary(client_conn),
                f"{config.LIBTELIO_BINARY_PATH_MAC_VM}/list_interfaces_with_router_property.py",
            ]).execute()
            interfaces_with_router_prop = process.get_stdout().splitlines()
            assert len(interfaces_with_router_prop) == 1
            assert VAGRANT_LIBVIRT_MANAGEMENT_IP in interfaces_with_router_prop[0]

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
                adapter_type_override=TelioAdapterType.BORING_TUN,
                connection_tracker_config=generate_connection_tracker_config(
                    ConnectionTag.DOCKER_CONE_CLIENT_1,
                    vpn_1_limits=ConnectionLimits(1, 1),
                    vpn_2_limits=ConnectionLimits(1, 1),
                    stun_limits=ConnectionLimits(1, 2),
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
                    vpn_1_limits=ConnectionLimits(1, 1),
                    vpn_2_limits=ConnectionLimits(1, 1),
                    stun_limits=ConnectionLimits(1, 2),
                ),
                is_meshnet=False,
            ),
            "10.0.254.1",
            marks=pytest.mark.linux_native,
        ),
        pytest.param(
            SetupParameters(
                connection_tag=ConnectionTag.WINDOWS_VM_1,
                adapter_type_override=TelioAdapterType.WINDOWS_NATIVE_TUN,
                connection_tracker_config=generate_connection_tracker_config(
                    ConnectionTag.WINDOWS_VM_1,
                    vpn_1_limits=ConnectionLimits(1, 1),
                    vpn_2_limits=ConnectionLimits(1, 1),
                    stun_limits=ConnectionLimits(1, 2),
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
                connection_tag=ConnectionTag.WINDOWS_VM_1,
                adapter_type_override=TelioAdapterType.WIREGUARD_GO_TUN,
                connection_tracker_config=generate_connection_tracker_config(
                    ConnectionTag.WINDOWS_VM_1,
                    vpn_1_limits=ConnectionLimits(1, 1),
                    vpn_2_limits=ConnectionLimits(1, 1),
                    stun_limits=ConnectionLimits(1, 2),
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
                connection_tag=ConnectionTag.MAC_VM,
                adapter_type_override=TelioAdapterType.BORING_TUN,
                connection_tracker_config=generate_connection_tracker_config(
                    ConnectionTag.MAC_VM,
                    vpn_1_limits=ConnectionLimits(1, 1),
                    vpn_2_limits=ConnectionLimits(1, 1),
                    stun_limits=ConnectionLimits(1, 2),
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
            setup_environment(exit_stack, [alpha_setup_params])
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
                adapter_type_override=TelioAdapterType.BORING_TUN,
                ip_stack=IPStack.IPv4,
                features=default_features(enable_firewall_connection_reset=True),
            )
        ),
        # TODO(msz): IPv6 public server, it doesn't work with the current VPN implementation
        # pytest.param(
        #     SetupParameters(
        #         connection_tag=ConnectionTag.DOCKER_OPEN_INTERNET_CLIENT_DUAL_STACK,
        #         adapter_type_override=TelioAdapterType.BORING_TUN,
        #         ip_stack=IPStack.IPv6,
        #         features=default_features(enable_firewall_connection_reset=True),
        #     )
        # ),
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
            setup_environment(exit_stack, [setup_params])
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

        close_event_1 = asyncio.Event()
        close_event_2 = asyncio.Event()

        async with ConnectionTracker(
            connection,
            [
                ConnectionTrackerConfig(
                    "nc",
                    ConnectionLimits(),
                    FiveTuple(protocol="tcp", dst_ip=serv_ip, dst_port=80),
                )
            ],
            True,
        ).run() as conntrack:
            conntrack.notify_on_tcp_state(TcpState.CLOSE, close_event_1)
            conntrack.notify_on_tcp_state(TcpState.CLOSE, close_event_2)

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
            await nc_client_2.receive_data()

            # the key is generated uniquely each time natlab runs
            await client.disconnect_from_vpn(str(config.WG_SERVER["public_key"]))

            await connect(
                config.WG_SERVER_2,
            )

            # under normal circumstances -> conntrack should show FIN_WAIT -> CLOSE_WAIT
            # But our connection killing mechanism will reset connection resulting in CLOSE output.
            # Wait for close on both clients
            await close_event_1.wait()
            await close_event_2.wait()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "setup_params",
    [
        # IPv4 public server
        pytest.param(
            SetupParameters(
                connection_tag=ConnectionTag.DOCKER_CONE_CLIENT_1,
                adapter_type_override=TelioAdapterType.BORING_TUN,
                ip_stack=IPStack.IPv4,
                features=default_features(enable_firewall_connection_reset=True),
            )
        ),
        pytest.param(
            SetupParameters(
                connection_tag=ConnectionTag.MAC_VM,
                adapter_type_override=TelioAdapterType.BORING_TUN,
                ip_stack=IPStack.IPv4,
                features=default_features(enable_firewall_connection_reset=True),
            ),
            marks=pytest.mark.mac,
        ),
        # TODO(msz): IPv6 public server, it doesn't work with the current VPN implementation
        # pytest.param(
        #     SetupParameters(
        #         connection_tag=ConnectionTag.DOCKER_OPEN_INTERNET_CLIENT_DUAL_STACK,
        #         adapter_type_override=TelioAdapterType.BORING_TUN,
        #         ip_stack=IPStack.IPv6,
        #         features=default_features(enable_firewall_connection_reset=True),
        #     )
        # ),
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
            setup_environment(exit_stack, [setup_params])
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
                adapter_type_override=TelioAdapterType.BORING_TUN,
                connection_tracker_config=generate_connection_tracker_config(
                    ConnectionTag.DOCKER_CONE_CLIENT_1,
                    stun_limits=ConnectionLimits(1, 1),
                    vpn_1_limits=ConnectionLimits(1, 1),
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
                    stun_limits=ConnectionLimits(1, 1),
                    vpn_1_limits=ConnectionLimits(1, 1),
                ),
                is_meshnet=False,
            ),
            "10.0.254.1",
            marks=pytest.mark.linux_native,
        ),
        pytest.param(
            SetupParameters(
                connection_tag=ConnectionTag.WINDOWS_VM_1,
                adapter_type_override=TelioAdapterType.WINDOWS_NATIVE_TUN,
                connection_tracker_config=generate_connection_tracker_config(
                    ConnectionTag.WINDOWS_VM_1,
                    stun_limits=ConnectionLimits(1, 1),
                    vpn_1_limits=ConnectionLimits(1, 1),
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
                connection_tag=ConnectionTag.WINDOWS_VM_1,
                adapter_type_override=TelioAdapterType.WIREGUARD_GO_TUN,
                connection_tracker_config=generate_connection_tracker_config(
                    ConnectionTag.WINDOWS_VM_1,
                    stun_limits=ConnectionLimits(1, 1),
                    vpn_1_limits=ConnectionLimits(1, 1),
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
                connection_tag=ConnectionTag.MAC_VM,
                adapter_type_override=TelioAdapterType.BORING_TUN,
                connection_tracker_config=generate_connection_tracker_config(
                    ConnectionTag.MAC_VM,
                    stun_limits=ConnectionLimits(1, 1),
                    vpn_1_limits=ConnectionLimits(1, 1),
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
            setup_environment(exit_stack, [alpha_setup_params])
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
