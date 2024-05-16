import asyncio
import config
import copy
import pytest
from contextlib import AsyncExitStack
from helpers import SetupParameters, setup_environment, setup_connections
from telio import AdapterType, Client
from telio_features import TelioFeatures
from typing import Optional
from utils import testing, stun
from utils.connection import Connection
from utils.connection_tracker import ConnectionLimits, ConnectionTrackerConfig
from utils.connection_util import generate_connection_tracker_config, ConnectionTag
from utils.output_notifier import OutputNotifier
from utils.ping import Ping
from utils.router import IPProto, IPStack


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

    async with Ping(client_conn, config.PHOTO_ALBUM_IP).run() as ping:
        await ping.wait_for_next_ping()

    if vpn_connection is not None:
        async with Ping(vpn_connection, client_meshnet_ip).run() as ping:
            await ping.wait_for_next_ping()

    ip = await testing.wait_long(stun.get(client_conn, config.STUN_SERVER))
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
                adapter_type=AdapterType.BoringTun,
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
                adapter_type=AdapterType.LinuxNativeWg,
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
                adapter_type=AdapterType.WindowsNativeWg,
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
                adapter_type=AdapterType.WireguardGo,
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
                adapter_type=AdapterType.BoringTun,
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

        ip = await testing.wait_long(stun.get(client_conn, config.STUN_SERVER))
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
                adapter_type=AdapterType.BoringTun,
                connection_tracker_config=generate_connection_tracker_config(
                    ConnectionTag.DOCKER_CONE_CLIENT_1,
                    vpn_1_limits=ConnectionLimits(1, 1),
                    vpn_2_limits=ConnectionLimits(1, 1),
                    stun_limits=ConnectionLimits(2, 2),
                ),
                is_meshnet=False,
            ),
            "10.0.254.1",
        ),
        pytest.param(
            SetupParameters(
                connection_tag=ConnectionTag.DOCKER_CONE_CLIENT_1,
                adapter_type=AdapterType.LinuxNativeWg,
                connection_tracker_config=generate_connection_tracker_config(
                    ConnectionTag.DOCKER_CONE_CLIENT_1,
                    vpn_1_limits=ConnectionLimits(1, 1),
                    vpn_2_limits=ConnectionLimits(1, 1),
                    stun_limits=ConnectionLimits(2, 2),
                ),
                is_meshnet=False,
            ),
            "10.0.254.1",
            marks=pytest.mark.linux_native,
        ),
        pytest.param(
            SetupParameters(
                connection_tag=ConnectionTag.WINDOWS_VM_1,
                adapter_type=AdapterType.WindowsNativeWg,
                connection_tracker_config=generate_connection_tracker_config(
                    ConnectionTag.WINDOWS_VM_1,
                    vpn_1_limits=ConnectionLimits(1, 1),
                    vpn_2_limits=ConnectionLimits(1, 1),
                    stun_limits=ConnectionLimits(2, 2),
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
                adapter_type=AdapterType.WireguardGo,
                connection_tracker_config=generate_connection_tracker_config(
                    ConnectionTag.WINDOWS_VM_1,
                    vpn_1_limits=ConnectionLimits(1, 1),
                    vpn_2_limits=ConnectionLimits(1, 1),
                    stun_limits=ConnectionLimits(2, 2),
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
                adapter_type=AdapterType.BoringTun,
                connection_tracker_config=generate_connection_tracker_config(
                    ConnectionTag.MAC_VM,
                    vpn_1_limits=ConnectionLimits(1, 1),
                    vpn_2_limits=ConnectionLimits(1, 1),
                    stun_limits=ConnectionLimits(2, 2),
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

        ip = await testing.wait_long(stun.get(connection, config.STUN_SERVER))
        assert ip == public_ip, f"wrong public IP before connecting to VPN {ip}"

        await _connect_vpn(
            connection,
            vpn_1_connection.connection,
            client_alpha,
            alpha.ip_addresses[0],
            config.WG_SERVER,
        )

        await client_alpha.disconnect_from_vpn(str(config.WG_SERVER["public_key"]))

        ip = await testing.wait_long(stun.get(connection, config.STUN_SERVER))
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
                connection_tag=ConnectionTag.DOCKER_OPEN_INTERNET_CLIENT_DUAL_STACK,
                adapter_type=AdapterType.BoringTun,
                ip_stack=IPStack.IPv4,
                features=TelioFeatures(boringtun_reset_connections=True),
            )
        ),
        # TODO(msz): IPv6 public server, it doesn't work with the current VPN implementation
        # pytest.param(
        #     SetupParameters(
        #         connection_tag=ConnectionTag.DOCKER_OPEN_INTERNET_CLIENT_DUAL_STACK,
        #         adapter_type=AdapterType.BoringTun,
        #         ip_stack=IPStack.IPv6,
        #         telio_features=TelioFeatures(boringtun_reset_connections=True),
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

            async with Ping(connection, serv_ip).run() as ping:
                await ping.wait_for_next_ping()

        await connect(
            config.WG_SERVER,
        )

        output_notifier = OutputNotifier()

        async def on_stdout(stdout: str) -> None:
            for line in stdout.splitlines():
                output_notifier.handle_output(line)

        async def conntrack_on_stdout(stdout: str) -> None:
            for line in stdout.splitlines():
                if f"dst={serv_ip}" in line:
                    output_notifier.handle_output(line)

        sender_start_event = asyncio.Event()
        close_wait_event = asyncio.Event()

        output_notifier.notify_output(
            "80 port [tcp/*] succeeded!",
            sender_start_event,
        )
        output_notifier.notify_output("CLOSE", close_wait_event)

        async with connection.create_process([
            "conntrack",
            "--family",
            "ipv6" if setup_params.ip_stack == IPStack.IPv6 else "ipv4",
            "-E",
        ]).run(stdout_callback=conntrack_on_stdout) as conntrack_proc:
            await conntrack_proc.wait_stdin_ready()

            ip_proto = (
                IPProto.IPv6 if setup_params.ip_stack == IPStack.IPv6 else IPProto.IPv4
            )
            alpha_ip = testing.unpack_optional(alpha.get_ip_address(ip_proto))

            await exit_stack.enter_async_context(
                connection.create_process([
                    "nc",
                    "-nv",
                    "-6" if setup_params.ip_stack == IPStack.IPv6 else "-4",
                    "-s",
                    alpha_ip,
                    serv_ip,
                    str(80),
                ]).run(stdout_callback=on_stdout, stderr_callback=on_stdout)
            )

            # Second client, this time sending some data to check proper TCP sequence number generation
            proc = await exit_stack.enter_async_context(
                connection.create_process([
                    "nc",
                    "-nv",
                    "-6" if setup_params.ip_stack == IPStack.IPv6 else "-4",
                    "-s",
                    alpha_ip,
                    serv_ip,
                    str(80),
                ]).run(stdout_callback=on_stdout, stderr_callback=on_stdout)
            )

            await proc.wait_stdin_ready()
            await asyncio.sleep(2.0)
            # Without this sleep nc get EOF on stdin for some reason
            await proc.write_stdin("GET")

            # Wait for both netcat processes
            await testing.wait_normal(sender_start_event.wait())
            await testing.wait_normal(sender_start_event.wait())

            # the key is generated uniquely each time natlab runs
            await client.disconnect_from_vpn(str(config.WG_SERVER["public_key"]))

            await connect(
                config.WG_SERVER_2,
            )

            # if everything is correct -> conntrack should show FIN_WAIT -> CLOSE_WAIT
            # or our connection killing mechanism will reset connection resulting in CLOSE output.
            # Wait for close on both clients
            await testing.wait_long(close_wait_event.wait())
            await testing.wait_long(close_wait_event.wait())


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "setup_params",
    [
        # IPv4 public server
        pytest.param(
            SetupParameters(
                connection_tag=ConnectionTag.DOCKER_OPEN_INTERNET_CLIENT_DUAL_STACK,
                adapter_type=AdapterType.BoringTun,
                ip_stack=IPStack.IPv4,
                features=TelioFeatures(boringtun_reset_connections=True),
            )
        ),
        # TODO(msz): IPv6 public server, it doesn't work with the current VPN implementation
        # pytest.param(
        #     SetupParameters(
        #         connection_tag=ConnectionTag.DOCKER_OPEN_INTERNET_CLIENT_DUAL_STACK,
        #         adapter_type=AdapterType.BoringTun,
        #         ip_stack=IPStack.IPv6,
        #         telio_features=TelioFeatures(boringtun_reset_connections=True),
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

            async with Ping(connection, serv_ip).run() as ping:
                await ping.wait_for_next_ping()

        await connect(
            config.WG_SERVER,
        )

        output_notifier = OutputNotifier()

        async def on_stdout(stdout: str) -> None:
            for line in stdout.splitlines():
                output_notifier.handle_output(line)

        sender_start_event = asyncio.Event()

        output_notifier.notify_output(
            "2000 port [udp/*] succeeded!",
            sender_start_event,
        )

        ip_proto = (
            IPProto.IPv6 if setup_params.ip_stack == IPStack.IPv6 else IPProto.IPv4
        )
        alpha_ip = testing.unpack_optional(alpha.get_ip_address(ip_proto))

        proc = connection.create_process([
            "nc",
            "-nuv",
            "-6" if setup_params.ip_stack == IPStack.IPv6 else "-4",
            "-s",
            alpha_ip,
            serv_ip,
            str(2000),
        ])

        await exit_stack.enter_async_context(
            proc.run(stdout_callback=on_stdout, stderr_callback=on_stdout)
        )

        await testing.wait_long(sender_start_event.wait())
        await client.disconnect_from_vpn(str(config.WG_SERVER["public_key"]))

        await connect(
            config.WG_SERVER_2,
        )

        # nc client should be closed by the reset mechanism
        await testing.wait_long(proc.is_done())
