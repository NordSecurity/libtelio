import json
import pytest
from config import (
    WG_SERVER,
    PHOTO_ALBUM_IP,
    STUN_SERVER,
    CORE_API_URL,
    CORE_API_BEARER_AUTHORIZATION_HEADER,
    LAN_ADDR_MAP,
)
from contextlib import AsyncExitStack
from helpers import setup_connections, send_https_request
from mesh_api import API
from pathlib import Path
from teliod import Teliod, Config, IfcConfigType, Paths
from utils import stun
from utils.connection import ConnectionTag
from utils.logger import log
from utils.ping import ping


@pytest.mark.asyncio
async def test_openwrt_vpn_connection() -> None:
    """
    Connect to vpn from OpenWRT router

    Steps:
        1. Prepare vpn servers
        2. Send post request to core-api to save public key of vpn server we are planning to use
        3. Start teliod in OpenWRT container
        4. Check ip address of both openwrt container and client node is equal to vpn ip address
        5. Ping PHOTO_ALBUM_IP from both openwrt and client node
        6. Check access to the OpenWRT config panel from the Client device
    """
    async with AsyncExitStack() as exit_stack:
        api = API()
        api.prepare_all_vpn_servers()
        connection = (
            await setup_connections(exit_stack, [ConnectionTag.DOCKER_OPENWRT_CLIENT_1])
        )[0]
        client_connection = connection.connection
        gateway_connection = connection.gw_connection
        assert gateway_connection is not None

        config_path = Paths(exec_path=Path("nordvpn"))
        teliod = Teliod(
            gateway_connection,
            exit_stack,
            config=Config(IfcConfigType.VPN_OPENWRT, paths=config_path),
        )

        # we only know the key of the VPN server at runtime and it needs to be in the config before starting teliod
        await gateway_connection.create_process([
            "sed",
            "-i",
            f's#"server_pubkey": .*#"server_pubkey": "{WG_SERVER["public_key"]}"#g',
            str(teliod.config.path()),
        ]).execute(privileged=True)

        # upload vpn public key to Core-Api server to be used in mocked data
        payload = json.dumps({"public_key": WG_SERVER["public_key"]})
        await send_https_request(
            gateway_connection,
            f"{CORE_API_URL}/test/public-key",
            "POST",
            "/etc/ssl/certs/test.pem",
            data=payload,
            authorization_header=CORE_API_BEARER_AUTHORIZATION_HEADER,
            expect_response=False,
        )

        async with teliod.start():
            log.debug("Teliod started, waiting for connected vpn state...")
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

            # check openwrt panel is accessible from client device
            await gateway_connection.create_process([
                "curl",
                "-I",
                f"http://{LAN_ADDR_MAP[ConnectionTag.DOCKER_OPENWRT_CLIENT_1]}",
            ]).execute()

            await gateway_connection.create_process([
                "sed",
                "-i",
                's#"server_pubkey": .*#"server_pubkey": "public-key-placeholder"#g',
                str(teliod.config.path()),
            ]).execute(privileged=True)
