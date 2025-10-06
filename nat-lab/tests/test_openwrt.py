import pytest
import re
from config import WG_SERVER, PHOTO_ALBUM_IP, STUN_SERVER, LAN_ADDR_MAP
from contextlib import AsyncExitStack
from helpers import setup_connections
from nordvpnlite import NordVpnLite, Config, IfcConfigType, Paths
from pathlib import Path
from utils import stun
from utils.connection import ConnectionTag
from utils.connection_util import new_connection_raw
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
        3. Start NordVPN Lite in OpenWRT container
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
        await gateway_connection.create_process(
            ["mkdir", "-p", "/etc/nordvpnlite"]
        ).execute()
        await gateway_connection.upload_file(
            f"data/nordvpnlite/{openwrt_config.value}",
            f"/etc/nordvpnlite/{openwrt_config.value}",
        )

        config_path = Paths(exec_path=Path("nordvpnlite"))
        nordvpnlite = NordVpnLite(
            gateway_connection,
            exit_stack,
            config=Config(openwrt_config, paths=config_path),
        )
        await nordvpnlite.request_credentials_from_core()

        async with nordvpnlite.start():
            log.debug("NordVPN Lite started, waiting for connected vpn state...")
            await nordvpnlite.wait_for_vpn_connected_state()
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


@pytest.mark.asyncio
@pytest.mark.openwrt
async def test_openwrt_ip_leaks() -> None:
    """
    Check all the traffic goes through the vpn after connection

    Steps:
        1. Prepare vpn servers
        2. Send post request to core-api to save public key of vpn server we are planning to use
        3. Start NordVPN Lite in OpenWRT container
        4. Start tcpdump on PHOTO ALBUM
        5. Ping PHOTO_ALBUM_IP from both openwrt and client node
        6. Initiate tcp connection from openwrt gateway and client to photo album
        7. Send udp packets from openwrt client to photo album
        8. Check tcpdump on gateway and client node - all IPs should be vpn ip
    """
    async with AsyncExitStack() as exit_stack:
        client_connection = (
            await setup_connections(exit_stack, [ConnectionTag.DOCKER_OPENWRT_CLIENT_1])
        )[0].connection
        gateway_connection = (
            await setup_connections(exit_stack, [ConnectionTag.VM_OPENWRT_GW_1])
        )[0].connection
        photo_album_connection = await exit_stack.enter_async_context(
            new_connection_raw(ConnectionTag.DOCKER_PHOTO_ALBUM)
        )
        await gateway_connection.create_process(
            ["mkdir", "-p", "/etc/nordvpnlite"]
        ).execute()
        await gateway_connection.upload_file(
            f"data/nordvpnlite/{IfcConfigType.VPN_OPENWRT_UCI_PL.value}",
            f"/etc/nordvpnlite/{IfcConfigType.VPN_OPENWRT_UCI_PL.value}",
        )

        config_path = Paths(exec_path=Path("nordvpnlite"))
        nordvpnlite = NordVpnLite(
            gateway_connection,
            exit_stack,
            config=Config(IfcConfigType.VPN_OPENWRT_UCI_PL, paths=config_path),
        )
        await nordvpnlite.request_credentials_from_core()

        async with nordvpnlite.start():
            log.debug("NordVPN Lite started, waiting for connected vpn state...")
            await nordvpnlite.wait_for_vpn_connected_state()
            async with photo_album_connection.create_process([
                "tcpdump",
                "--immediate-mode",
                "-l",
                "-i",
                "eth0",
                "-nn",
            ]).run() as tcp_dump:
                await ping(gateway_connection, PHOTO_ALBUM_IP)
                await ping(client_connection, PHOTO_ALBUM_IP)
                await gateway_connection.create_process(
                    ["sh", "-c", f"echo -n | nc {PHOTO_ALBUM_IP} 80 >/dev/null 2>&1"]
                ).execute()
                await client_connection.create_process([
                    "bash",
                    "-c",
                    f"echo -n | nc -N {PHOTO_ALBUM_IP} 80 >/dev/null 2>&1",
                ]).execute()
                # send udp packet from openwrt client device
                await client_connection.create_process(
                    ["bash", "-c", f"echo 'ping' | nc -u -w 1 {PHOTO_ALBUM_IP} 12345"]
                ).execute()
                # split tcpump by date time
                pattern = (
                    r"(?=(?:\d{4}-\d{2}-\d{2}\s+)?\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?)"
                )
                lines = re.split(pattern, tcp_dump.get_stdout())
                tcp_dump_lines = [line.strip() for line in lines if line.strip()]
                leak_ips = [
                    "10.0.0.0",
                    LAN_ADDR_MAP[ConnectionTag.DOCKER_OPENWRT_CLIENT_1],
                    LAN_ADDR_MAP[ConnectionTag.VM_OPENWRT_GW_1],
                ]

                errors = [
                    f"Leaked IP - {ip}, log line - {line}"
                    for line in tcp_dump_lines
                    for ip in leak_ips
                    if ip in line
                ]
                assert not errors, "Next IPs were leaked:\n" + "\n".join(errors)
