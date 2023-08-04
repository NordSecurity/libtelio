import pytest
import utils.testing as testing
from contextlib import AsyncExitStack
import config
from mesh_api import API
from telio import AdapterType, PathType, Client, State
from utils import (
    Connection,
    ConnectionTag,
    new_connection_with_conn_tracker,
    stun,
    Ping,
)
from utils.connection_tracker import (
    ConnectionTracker,
    ConnectionLimits,
    generate_connection_tracker_config,
)


async def _connect_vpn(
    connection: Connection,
    conn_tracker: ConnectionTracker,
    client: Client,
    wg_server: dict,
    connection_key: str,
) -> None:
    await testing.wait_long(
        client.connect_to_vpn(
            wg_server["ipv4"], wg_server["port"], wg_server["public_key"]
        )
    )

    await testing.wait_lengthy(
        client.wait_for_state_peer(
            wg_server["public_key"], [State.Connected], [PathType.Direct]
        )
    )

    await testing.wait_long(conn_tracker.wait_for_event(connection_key))

    async with Ping(connection, config.PHOTO_ALBUM_IP).run() as ping:
        await testing.wait_long(ping.wait_for_next_ping())

    ip = await testing.wait_long(stun.get(connection, config.STUN_SERVER))
    assert ip == wg_server["ipv4"], f"wrong public IP when connected to VPN {ip}"


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
async def test_vpn_connection(
    alpha_connection_tag: ConnectionTag,
    adapter_type: AdapterType,
    public_ip: str,
) -> None:
    async with AsyncExitStack() as exit_stack:
        api = API()
        alpha = api.default_config_alpha_node()
        (connection, conn_tracker) = await exit_stack.enter_async_context(
            new_connection_with_conn_tracker(
                alpha_connection_tag,
                generate_connection_tracker_config(
                    alpha_connection_tag,
                    vpn_1_limits=ConnectionLimits(1, 1),
                    stun_limits=ConnectionLimits(1, 1),
                ),
            )
        )

        ip = await testing.wait_long(stun.get(connection, config.STUN_SERVER))
        assert ip == public_ip, f"wrong public IP before connecting to VPN {ip}"
        await testing.wait_long(conn_tracker.wait_for_event("stun"))

        client_alpha = await exit_stack.enter_async_context(
            Client(connection, alpha, adapter_type).run()
        )
        await _connect_vpn(
            connection, conn_tracker, client_alpha, config.WG_SERVER, "vpn_1"
        )
        assert conn_tracker.get_out_of_limits() is None


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
async def test_vpn_reconnect(
    alpha_connection_tag: ConnectionTag,
    adapter_type: AdapterType,
    public_ip: str,
) -> None:
    async with AsyncExitStack() as exit_stack:
        api = API()

        alpha = api.default_config_alpha_node()
        (connection, conn_tracker) = await exit_stack.enter_async_context(
            new_connection_with_conn_tracker(
                alpha_connection_tag,
                generate_connection_tracker_config(
                    alpha_connection_tag,
                    vpn_1_limits=ConnectionLimits(1, 1),
                    vpn_2_limits=ConnectionLimits(1, 1),
                    stun_limits=ConnectionLimits(2, 2),
                ),
            )
        )

        ip = await testing.wait_long(stun.get(connection, config.STUN_SERVER))
        assert ip == public_ip, f"wrong public IP before connecting to VPN {ip}"

        client_alpha = await exit_stack.enter_async_context(
            Client(connection, alpha, adapter_type).run()
        )

        await _connect_vpn(
            connection, conn_tracker, client_alpha, config.WG_SERVER, "vpn_1"
        )

        await testing.wait_long(
            client_alpha.disconnect_from_vpn(
                config.WG_SERVER["public_key"], [PathType.Direct]
            )
        )

        ip = await testing.wait_long(stun.get(connection, config.STUN_SERVER))
        assert ip == public_ip, f"wrong public IP before connecting to VPN {ip}"

        await _connect_vpn(
            connection, conn_tracker, client_alpha, config.WG_SERVER_2, "vpn_2"
        )
        assert conn_tracker.get_out_of_limits() is None
