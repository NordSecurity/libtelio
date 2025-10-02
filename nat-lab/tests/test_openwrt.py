import pytest
from config import WG_SERVER, WG_SERVER_2, PHOTO_ALBUM_IP, STUN_SERVER
from contextlib import AsyncExitStack
from helpers import setup_connections
from nordvpnlite import NordVpnLite, Config, IfcConfigType, Paths
from pathlib import Path
from utils import stun
from utils.connection import Connection, ConnectionTag
from utils.logger import log
from utils.ping import ping


async def check_gateway_and_client_ip(
    gateway_connection: Connection,
    client_connection: Connection,
    expected_ip: str | int,
) -> None:
    """
    Verify that both the OpenWRT gateway and the client device obtain the expected
    IP address when connected to or disconnected from the VPN.

    This function performs two checks:
      1. Ensures that the gateway can reach PHOTO_ALBUM_IP and that
         its public IP, as reported by STUN, matches the expected IP.
      2. Ensures that the client device can also reach the same host and that
         its public IP matches the expected IP.

    Args:
        gateway_connection (Connection):
            An active SSH or Docker connection to the OpenWRT gateway.
        client_connection (Connection):
            An active SSH or Docker connection to the client device behind the gateway.
        expected_ip (str):
            The public IP address that both the gateway and client are expected to have
            when connected to or disconnected from the VPN.

    Raises:
        AssertionError:
            If either the gateway or the client reports a public IP different from
            `expected_ip`.
    Returns:
        None
    """
    await ping(gateway_connection, PHOTO_ALBUM_IP)
    gw_ip = await stun.get(gateway_connection, STUN_SERVER)
    assert gw_ip == expected_ip, (
        f"OpenWRT gateway has wrong public IP when connected to VPN: {gw_ip}. "
        f"Expected value: {expected_ip}"
    )

    await ping(client_connection, PHOTO_ALBUM_IP)
    client_ip = await stun.get(client_connection, STUN_SERVER)
    assert client_ip == expected_ip, (
        f"Client device has wrong public IP when connected to VPN: {client_ip}. "
        f"Expected value: {expected_ip}"
    )


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
            await check_gateway_and_client_ip(
                gateway_connection, client_connection, WG_SERVER["ipv4"]
            )


@pytest.mark.asyncio
@pytest.mark.openwrt
async def test_openwrt_vpn_reconnect() -> None:
    """
    Test re-connect to vpn from OpenWRT router

    Steps:
        1. Prepare vpn servers
        2. Start NordVPN Lite in OpenWRT container
        3. Check ip address of both openwrt container and client node is equal to vpn ip address
        4. Ping PHOTO_ALBUM_IP from both openwrt and client node
        5. Disconnect from vpn
        6. Check PHOTO_ALBUM_IP is reachable and ip addresses are equal to public ips
        7. Connect to vpn again with the same config (start NordVPN Lite)
        8. Check ip address of both openwrt container and client node is equal to vpn ip address
        9. Ping PHOTO_ALBUM_IP from both openwrt and client node

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
            await check_gateway_and_client_ip(
                gateway_connection, client_connection, WG_SERVER["ipv4"]
            )

        log.debug("Check connection after disconnect from vpn")
        await check_gateway_and_client_ip(
            gateway_connection, client_connection, "10.0.0.0"
        )

        async with nordvpnlite.start():
            log.debug("Reconnect to VPN...")
            await nordvpnlite.wait_for_vpn_connected_state()
            await check_gateway_and_client_ip(
                gateway_connection, client_connection, WG_SERVER["ipv4"]
            )


@pytest.mark.asyncio
@pytest.mark.openwrt
async def test_openwrt_vpn_reconnect_different_country() -> None:
    """
    Test re-connect to vpn server of another country

    Steps:
        1. Prepare vpn servers
        2. Connect to PL vpn server
        3. Check ip address of both openwrt container and client node is equal to vpn ip address
        4. Ping PHOTO_ALBUM_IP from both openwrt and client node
        5. Disconnect from vpn
        6. Check PHOTO_ALBUM_IP is reachable and ip addresses are equal to public ips
        7. Connect to DE vpn server
        8. Check ip address of both openwrt container and client node is equal to vpn ip address
        9. Ping PHOTO_ALBUM_IP from both openwrt and client node

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
            f"data/nordvpnlite/{IfcConfigType.VPN_OPENWRT_UCI_PL.value}",
            f"/etc/nordvpnlite/{IfcConfigType.VPN_OPENWRT_UCI_PL.value}",
        )
        await gateway_connection.upload_file(
            f"data/nordvpnlite/{IfcConfigType.VPN_OPENWRT_UCI_DE.value}",
            f"/etc/nordvpnlite/{IfcConfigType.VPN_OPENWRT_UCI_DE.value}",
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
            await check_gateway_and_client_ip(
                gateway_connection, client_connection, WG_SERVER["ipv4"]
            )

        log.debug("Check connection after disconnect from vpn")
        await check_gateway_and_client_ip(
            gateway_connection, client_connection, "10.0.0.0"
        )

        nordvpnlite_de = NordVpnLite(
            gateway_connection,
            exit_stack,
            config=Config(IfcConfigType.VPN_OPENWRT_UCI_DE, paths=config_path),
        )
        async with nordvpnlite_de.start():
            log.debug("Reconnect to VPN DE...")
            await nordvpnlite_de.wait_for_vpn_connected_state()
            await check_gateway_and_client_ip(
                gateway_connection, client_connection, WG_SERVER_2["ipv4"]
            )
