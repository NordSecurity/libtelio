import asyncio
import pytest
from config import WG_SERVER, PHOTO_ALBUM_IP, STUN_SERVER
from contextlib import AsyncExitStack
from helpers import setup_connections
from pathlib import Path
from teliod import Teliod, Config, IfcConfigType, Paths
from utils import stun
from utils.connection import ConnectionTag
from utils.logger import log
from utils.ping import ping


@pytest.mark.asyncio
@pytest.mark.openwrt
@pytest.mark.parametrize(
    "openwrt_config",
    [
        IfcConfigType.VPN_OPENWRT_UCI_PL,
    ],
)
async def test_openwrt_vpn_connection(openwrt_config: IfcConfigType) -> None:
    """
    Connect to vpn from OpenWRT router

    Steps:
        1. Prepare vpn servers
        2. Send post request to core-api to save public key of vpn server we are planning to use
        3. Start teliod in OpenWRT container
        4. Check ip address of both openwrt container and client node is equal to vpn ip address
        5. Ping PHOTO_ALBUM_IP from both openwrt and client node
    """
    async with AsyncExitStack() as exit_stack:
        client_connection = (
            await setup_connections(exit_stack, [ConnectionTag.DOCKER_OPENWRT_CLIENT_1])
        )[0].connection
        gateway_connection = (
            await setup_connections(exit_stack, [ConnectionTag.VM_OPENWRT_GW_1])
        )[0].connection
        assert gateway_connection is not None
        await gateway_connection.create_process(
            ["mkdir", "-p", "/etc/teliod"]
        ).execute()
        await gateway_connection.upload_file(
            f"data/teliod/{openwrt_config.value}",
            f"/etc/teliod/{openwrt_config.value}",
        )

        config_path = Paths(exec_path=Path("nordvpn"))
        teliod = Teliod(
            gateway_connection,
            exit_stack,
            config=Config(openwrt_config, paths=config_path),
        )
        await teliod.request_credentials_from_core()

        async with teliod.start():
            log.debug("Teliod started, waiting for connected vpn state...")
            # Add temporary time sleep due to race condition
            # ConnectToExitNode interrupts getStatus
            # remove when properly fixed
            await asyncio.sleep(2)
            await teliod.wait_for_vpn_connected_state()
            await ping(gateway_connection, PHOTO_ALBUM_IP)
            gw_ip = await stun.get(gateway_connection, STUN_SERVER)
            assert gw_ip == WG_SERVER["ipv4"], (
                f"OpenWRT gateway has wrong public IP when connected to VPN: {gw_ip}. "
                f"Expected value: {WG_SERVER['ipv4']}"
            )

            await ping(client_connection, PHOTO_ALBUM_IP)
            client_ip = await stun.get(client_connection, STUN_SERVER)
            assert client_ip == WG_SERVER["ipv4"], (
                f"Client device has wrong public IP when connected to VPN: {client_ip}. "
                f"Expected value: {WG_SERVER['ipv4']}"
            )
