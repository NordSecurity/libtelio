import config
import pytest
from contextlib import AsyncExitStack
from helpers import SetupParameters, setup_environment, setup_connections
from telio import AdapterType, Client
from utils import testing, stun
from utils.connection import Connection
from utils.connection_tracker import ConnectionLimits
from utils.connection_util import (
    ConnectionLimits,
    generate_connection_tracker_config,
    ConnectionTag,
)
from utils.ping import Ping


async def _connect_vpn(
    connection: Connection,
    vpn_connection: Connection,
    client: Client,
    client_meshnet_ip: str,
    wg_server: dict,
) -> None:
    await client.connect_to_vpn(
        wg_server["ipv4"], wg_server["port"], wg_server["public_key"]
    )

    async with Ping(connection, config.PHOTO_ALBUM_IP).run() as ping:
        await testing.wait_long(ping.wait_for_next_ping())

    async with Ping(vpn_connection, client_meshnet_ip).run() as ping:
        await testing.wait_long(ping.wait_for_next_ping())

    ip = await testing.wait_long(stun.get(connection, config.STUN_SERVER))
    assert ip == wg_server["ipv4"], f"wrong public IP when connected to VPN {ip}"


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
                    vpn_1_limits=ConnectionLimits(1, 1),
                    stun_limits=ConnectionLimits(1, 1),
                ),
                is_meshnet=False,
            ),
            "10.0.254.1",
            marks=pytest.mark.linux_native,
        ),
        pytest.param(
            SetupParameters(
                connection_tag=ConnectionTag.WINDOWS_VM,
                adapter_type=AdapterType.WindowsNativeWg,
                connection_tracker_config=generate_connection_tracker_config(
                    ConnectionTag.WINDOWS_VM,
                    vpn_1_limits=ConnectionLimits(1, 1),
                    stun_limits=ConnectionLimits(1, 1),
                ),
                is_meshnet=False,
            ),
            "10.0.254.7",
            marks=pytest.mark.windows,
        ),
        pytest.param(
            SetupParameters(
                connection_tag=ConnectionTag.WINDOWS_VM,
                adapter_type=AdapterType.WireguardGo,
                connection_tracker_config=generate_connection_tracker_config(
                    ConnectionTag.WINDOWS_VM,
                    vpn_1_limits=ConnectionLimits(1, 1),
                    stun_limits=ConnectionLimits(1, 1),
                ),
                is_meshnet=False,
            ),
            "10.0.254.7",
            marks=pytest.mark.windows,
        ),
        pytest.param(
            SetupParameters(
                connection_tag=ConnectionTag.MAC_VM,
                adapter_type=AdapterType.BoringTun,
                connection_tracker_config=generate_connection_tracker_config(
                    ConnectionTag.MAC_VM,
                    vpn_1_limits=ConnectionLimits(1, 1),
                    stun_limits=ConnectionLimits(1, 1),
                ),
                is_meshnet=False,
            ),
            "10.0.254.7",
            marks=pytest.mark.mac,
        ),
    ],
)
async def test_vpn_connection(
    alpha_setup_params: SetupParameters, public_ip: str
) -> None:
    async with AsyncExitStack() as exit_stack:
        env = await exit_stack.enter_async_context(
            setup_environment(exit_stack, [alpha_setup_params])
        )

        alpha, *_ = env.nodes
        connection, *_ = [conn.connection for conn in env.connections]
        client_alpha, *_ = env.clients

        vpn_connection, *_ = await setup_connections(
            exit_stack, [ConnectionTag.DOCKER_VPN_1]
        )

        ip = await testing.wait_long(stun.get(connection, config.STUN_SERVER))
        assert ip == public_ip, f"wrong public IP before connecting to VPN {ip}"

        await _connect_vpn(
            connection,
            vpn_connection.connection,
            client_alpha,
            alpha.ip_addresses[0],
            config.WG_SERVER,
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
                connection_tag=ConnectionTag.WINDOWS_VM,
                adapter_type=AdapterType.WindowsNativeWg,
                connection_tracker_config=generate_connection_tracker_config(
                    ConnectionTag.WINDOWS_VM,
                    vpn_1_limits=ConnectionLimits(1, 1),
                    vpn_2_limits=ConnectionLimits(1, 1),
                    stun_limits=ConnectionLimits(2, 2),
                ),
                is_meshnet=False,
            ),
            "10.0.254.7",
            marks=pytest.mark.windows,
        ),
        pytest.param(
            SetupParameters(
                connection_tag=ConnectionTag.WINDOWS_VM,
                adapter_type=AdapterType.WireguardGo,
                connection_tracker_config=generate_connection_tracker_config(
                    ConnectionTag.WINDOWS_VM,
                    vpn_1_limits=ConnectionLimits(1, 1),
                    vpn_2_limits=ConnectionLimits(1, 1),
                    stun_limits=ConnectionLimits(2, 2),
                ),
                is_meshnet=False,
            ),
            "10.0.254.7",
            marks=pytest.mark.windows,
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
