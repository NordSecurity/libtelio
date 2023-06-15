import pytest
import telio
import utils.testing as testing
from typing import Optional, List
from contextlib import AsyncExitStack
import config
from mesh_api import API
from telio import AdapterType, PathType
from utils import ConnectionTag, new_connection_with_conn_tracker, stun, Ping
from utils.connection_tracker import (
    ConnectionTrackerConfig,
    ConnectionLimits,
    FiveTuple,
)


LINUX_CONNECTION_TRACKER_CONFIG = [
    ConnectionTrackerConfig(
        "vpn",
        ConnectionLimits(min=1, max=1),
        FiveTuple(
            src_ip=config.DOCKER_CONE_CLIENT_1_LAN_ADDR,
            dst_ip=str(config.WG_SERVER.get("ipv4")),
            dst_port=51820,
        ),
    ),
    ConnectionTrackerConfig(
        "stun_1",
        ConnectionLimits(min=1, max=1),
        FiveTuple(
            src_ip=config.DOCKER_CONE_CLIENT_1_LAN_ADDR,
            dst_ip=config.STUN_SERVER,
            dst_port=3478,
        ),
    ),
    ConnectionTrackerConfig(
        "stun_2",
        ConnectionLimits(min=1, max=1),
        FiveTuple(
            src_ip=config.ALPHA_NODE_ADDRESS, dst_ip=config.STUN_SERVER, dst_port=3478
        ),
    ),
    ConnectionTrackerConfig(
        "ping",
        ConnectionLimits(min=1),
        FiveTuple(src_ip=config.ALPHA_NODE_ADDRESS, dst_ip=config.PHOTO_ALBUM_IP),
    ),
    ConnectionTrackerConfig(
        "general_connections",
        ConnectionLimits(min=4),
        FiveTuple(),
    ),
]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "alpha_connection_tag,adapter_type,public_ip,conn_tracker_config",
    [
        pytest.param(
            ConnectionTag.DOCKER_CONE_CLIENT_1,
            AdapterType.BoringTun,
            "10.0.254.1",
            LINUX_CONNECTION_TRACKER_CONFIG,
        ),
        pytest.param(
            ConnectionTag.DOCKER_CONE_CLIENT_1,
            AdapterType.LinuxNativeWg,
            "10.0.254.1",
            LINUX_CONNECTION_TRACKER_CONFIG,
            marks=pytest.mark.linux_native,
        ),
        pytest.param(
            ConnectionTag.WINDOWS_VM,
            AdapterType.WindowsNativeWg,
            "10.0.254.7",
            None,
            marks=pytest.mark.windows,
        ),
        pytest.param(
            ConnectionTag.WINDOWS_VM,
            AdapterType.WireguardGo,
            "10.0.254.7",
            None,
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
async def test_vpn_connection(
    alpha_connection_tag: ConnectionTag,
    adapter_type: AdapterType,
    public_ip: str,
    conn_tracker_config: Optional[List[ConnectionTrackerConfig]],
) -> None:
    async with AsyncExitStack() as exit_stack:
        api = API()
        (alpha, _, _) = api.default_config_three_nodes()
        (connection, conn_tracker) = await exit_stack.enter_async_context(
            new_connection_with_conn_tracker(alpha_connection_tag, conn_tracker_config)
        )

        ip = await testing.wait_long(stun.get(connection, config.STUN_SERVER))
        assert ip == public_ip, f"wrong public IP before connecting to VPN {ip}"
        await testing.wait_long(conn_tracker.wait_for_event("stun_1"))

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
            client_alpha.handshake(wg_server["public_key"], PathType.Direct)
        )

        await testing.wait_long(conn_tracker.wait_for_event("vpn"))

        async with Ping(connection, config.PHOTO_ALBUM_IP) as ping:
            await testing.wait_long(ping.wait_for_next_ping())

        await testing.wait_long(conn_tracker.wait_for_event("ping"))

        ip = await testing.wait_long(stun.get(connection, config.STUN_SERVER))
        assert ip == wg_server["ipv4"], f"wrong public IP when connected to VPN {ip}"

        # wait for connection tracker to catch last event
        await testing.wait_long(conn_tracker.wait_for_event("stun_2"))
        assert conn_tracker.get_out_of_limits() is None
