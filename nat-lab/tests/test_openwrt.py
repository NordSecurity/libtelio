import asyncio
import pytest
import re
from config import WG_SERVER, WG_SERVER_2, PHOTO_ALBUM_IP, STUN_SERVER, LAN_ADDR_MAP
from contextlib import AsyncExitStack
from helpers import print_network_state, wait_for_interface_state, wait_for_log_line
from nordvpnlite import NordVpnLite, Config, IfcConfigType, Paths
from pathlib import Path
from utils import stun
from utils.connection import Connection, ConnectionTag
from utils.connection_util import new_connection_raw, new_connection_by_tag
from utils.logger import log
from utils.openwrt import start_logread_process
from utils.ping import ping
from utils.process import ProcessExecError

NETWORK_RESTART_LOG_LINE = "netifd: Network device 'eth1' link is up"
OPENWRT_GW_WAN_IP = "10.0.0.0"


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
      3. Ensures that LuCi UI is available from the client device when
         connected to or disconnected from the VPN.

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
            `expected_ip` and if LuCi UI isn't available from the client device.
    Returns:
        None
    """
    try:
        await ping(gateway_connection, PHOTO_ALBUM_IP)
    except ProcessExecError:
        dm = await gateway_connection.create_process(["dmesg"]).execute()
        dmesg_tail = "\n".join(dm.get_stdout().splitlines()[-100:])
        log.debug("dmesg tail:\n%s", dmesg_tail)

        lr = await gateway_connection.create_process(["logread"]).execute()
        logread_tail = "\n".join(lr.get_stdout().splitlines()[-100:])
        log.debug("logread tail:\n%s", logread_tail)

        free_out = await gateway_connection.create_process(["free"]).execute()
        log.debug("free (snapshot):\n%s", free_out.get_stdout())

        raise

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
    luci_ui_response = await client_connection.create_process([
        "sh",
        "-c",
        f'curl -s -o /dev/null -w "%{{http_code}}" http://{LAN_ADDR_MAP[ConnectionTag.VM_OPENWRT_GW_1]["primary"]}/',
    ]).execute()
    luci_ui_response_status = luci_ui_response.get_stdout().strip()
    assert (
        luci_ui_response_status == "200"
    ), f"LuCi UI isn't available. Response status: {luci_ui_response_status}"


async def setup_openwrt_test_environment(
    country_config: IfcConfigType,
    exit_stack: AsyncExitStack,
) -> tuple[Connection, Connection, NordVpnLite]:
    """
    Set up the OpenWrt test environment.

    This function establishes SSH connections to the OpenWrt gateway and client
    virtual machines, uploads configuration files to the gateway, initializes
    the VpnLite daemon interface for managing the VPN service, and prepares
    mock data for a third-party API used during tests.

    Args:
        country_config (IfcConfigType):
            Country config for which the OpenWrt environment
            should be configured.
        exit_stack (AsyncExitStack)

    Returns:
        tuple[Connection, Connection, VpnLite]:
            A tuple containing:
            - `client_connection`: connection to the OpenWrt client VM.
            - `gateway_connection`: connection to the OpenWrt gateway VM.
            - `nordvpnlite`: Instance of `NordVpnLite` class used to manage the daemon.
    """
    client_connection = await exit_stack.enter_async_context(
        new_connection_by_tag(ConnectionTag.DOCKER_OPENWRT_CLIENT_1)
    )
    gateway_connection = await exit_stack.enter_async_context(
        new_connection_by_tag(ConnectionTag.VM_OPENWRT_GW_1)
    )
    # printing networking state before test execution
    await print_network_state(gateway_connection)

    await gateway_connection.create_process(
        ["mkdir", "-p", "/etc/nordvpnlite"]
    ).execute()
    await gateway_connection.upload_file(
        f"data/nordvpnlite/{country_config.value}",
        f"/etc/nordvpnlite/{country_config.value}",
    )

    config_path = Paths(exec_path=Path("nordvpnlite"))
    nordvpnlite = NordVpnLite(
        gateway_connection,
        exit_stack,
        config=Config(country_config, paths=config_path),
    )
    await nordvpnlite.request_credentials_from_core()
    return client_connection, gateway_connection, nordvpnlite


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
        # setting up openwrt environment
        client_connection, gateway_connection, nordvpnlite = (
            await setup_openwrt_test_environment(openwrt_config, exit_stack)
        )

        async def grep_logread(s: str) -> list[str]:
            sshproc = await gateway_connection.create_process(
                ["logread", "-e", s]
            ).execute()
            lines = sshproc.get_stdout().splitlines()
            log.debug("<logread>")
            log.debug(lines)
            log.debug("</logread>")
            return lines

        # Restarting the log daemon clears the log. This makes the testcase safe to be execute in any order.
        await gateway_connection.create_process(
            ["/etc/init.d/log", "restart"]
        ).execute()
        await gateway_connection.create_process(
            ["/etc/init.d/dnsmasq", "restart"]
        ).execute()

        # Dnsmasq restart will populate the logs soon
        await asyncio.sleep(5)

        ns_lines = await grep_logread("nameserver")
        assert len(ns_lines) == 1
        assert "daemon.info dnsmasq[1]: using nameserver 10.0.80.82" in ns_lines[0]

        async with nordvpnlite.start():
            log.debug("NordVPN Lite started, waiting for connected vpn state...")
            await nordvpnlite.wait_for_vpn_connected_state()
            await check_gateway_and_client_ip(
                gateway_connection, client_connection, WG_SERVER["ipv4"]
            )
            logread_proc = await start_logread_process(
                gateway_connection, exit_stack, NETWORK_RESTART_LOG_LINE
            )
        await wait_for_log_line(logread_proc)
        log.info("Network has been reloaded")

        # Dnsmasq restart will populate the logs soon
        await asyncio.sleep(5)

        # check if DHCP DNS nameservers were restored
        ns_lines = await grep_logread("nameserver")
        assert len(ns_lines) == 3
        assert "daemon.info dnsmasq[1]: using nameserver 10.0.80.82" in ns_lines[0]
        assert "daemon.info dnsmasq[1]: using nameserver 10.0.80.83" in ns_lines[1]
        assert "daemon.info dnsmasq[1]: using nameserver 10.0.80.82" in ns_lines[2]


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
        8. Check tcpdump collected on PHOTO ALBUM - all IPs should be vpn ip
    """
    async with AsyncExitStack() as exit_stack:
        # setting up openwrt environment
        client_connection, gateway_connection, nordvpnlite = (
            await setup_openwrt_test_environment(
                IfcConfigType.VPN_OPENWRT_UCI_PL, exit_stack
            )
        )
        photo_album_connection = await exit_stack.enter_async_context(
            new_connection_raw(ConnectionTag.DOCKER_PHOTO_ALBUM)
        )

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
                # wrapping into asyncio.wait_for as BusyBox nc doesn't support timeouts
                await asyncio.wait_for(
                    gateway_connection.create_process([
                        "sh",
                        "-c",
                        f"echo -n | nc {PHOTO_ALBUM_IP} 80 >/dev/null 2>&1",
                    ]).execute(),
                    timeout=3,
                )
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
                    OPENWRT_GW_WAN_IP,
                    LAN_ADDR_MAP[ConnectionTag.DOCKER_OPENWRT_CLIENT_1]["primary"],
                    LAN_ADDR_MAP[ConnectionTag.VM_OPENWRT_GW_1]["primary"],
                ]

                errors = [
                    f"Leaked IP - {ip}, log line - {line}"
                    for line in tcp_dump_lines
                    for ip in leak_ips
                    if ip in line
                ]
                assert not errors, "Next IPs were leaked:\n" + "\n".join(errors)
            logread_proc = await start_logread_process(
                gateway_connection, exit_stack, NETWORK_RESTART_LOG_LINE
            )
        await wait_for_log_line(logread_proc)
        log.info("Network has been reloaded")


@pytest.mark.asyncio
@pytest.mark.openwrt
async def test_openwrt_simulate_network_down() -> None:
    """
    Check vpn connection is restored after network disconnect

    Steps:
        1. Prepare vpn servers
        2. Send post request to core-api to save public key of vpn server we are planning to use
        3. Start NordVPN Lite in OpenWRT container
        4. Check ip address of both openwrt container and client node is equal to vpn ip address
        5. Ping PHOTO_ALBUM_IP from both openwrt and client node
        6. Simulate wan network down
        7. Check ip address of both openwrt container and client node is equal to vpn ip address
        8. Ping PHOTO_ALBUM_IP from both openwrt and client node
    """
    async with AsyncExitStack() as exit_stack:
        # setting up openwrt environment
        client_connection, gateway_connection, nordvpnlite = (
            await setup_openwrt_test_environment(
                IfcConfigType.VPN_OPENWRT_UCI_PL, exit_stack
            )
        )

        async with nordvpnlite.start():
            log.debug("NordVPN Lite started, waiting for connected vpn state...")
            await nordvpnlite.wait_for_vpn_connected_state()
            await check_gateway_and_client_ip(
                gateway_connection, client_connection, WG_SERVER["ipv4"]
            )
            # simulating network interface down
            await gateway_connection.create_process(["ifdown", "wan"]).execute()
            if not await wait_for_interface_state(gateway_connection, "eth1", "DOWN"):
                raise Exception("Failed to set interface eth1 DOWN")

            # setting wan interface back
            await gateway_connection.create_process(["ifup", "wan"]).execute()
            if not await wait_for_interface_state(gateway_connection, "eth1", "UP"):
                raise Exception("Failed to set interface eth1 UP")
            # check vpn connection is working after interface is UP
            await check_gateway_and_client_ip(
                gateway_connection, client_connection, WG_SERVER["ipv4"]
            )
            logread_proc = await start_logread_process(
                gateway_connection, exit_stack, NETWORK_RESTART_LOG_LINE
            )
        await wait_for_log_line(logread_proc)
        log.info("Network has been reloaded")


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
        # setting up openwrt environment
        client_connection, gateway_connection, nordvpnlite = (
            await setup_openwrt_test_environment(
                IfcConfigType.VPN_OPENWRT_UCI_PL, exit_stack
            )
        )

        async with nordvpnlite.start():
            log.debug("NordVPN Lite started, waiting for connected vpn state...")
            await nordvpnlite.wait_for_vpn_connected_state()
            await check_gateway_and_client_ip(
                gateway_connection, client_connection, WG_SERVER["ipv4"]
            )
            logread_proc = await start_logread_process(
                gateway_connection, exit_stack, NETWORK_RESTART_LOG_LINE
            )
        await wait_for_log_line(logread_proc)
        log.info("Network has been reloaded")

        log.debug("Check connection after disconnect from vpn")
        await check_gateway_and_client_ip(
            gateway_connection, client_connection, OPENWRT_GW_WAN_IP
        )

        async with nordvpnlite.start():
            log.debug("Reconnect to VPN...")
            await nordvpnlite.wait_for_vpn_connected_state()
            await check_gateway_and_client_ip(
                gateway_connection, client_connection, WG_SERVER["ipv4"]
            )
            logread_proc = await start_logread_process(
                gateway_connection, exit_stack, NETWORK_RESTART_LOG_LINE
            )
        await wait_for_log_line(logread_proc)
        log.info("Network has been reloaded")


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
        # setting up openwrt environment
        client_connection, gateway_connection, nordvpnlite = (
            await setup_openwrt_test_environment(
                IfcConfigType.VPN_OPENWRT_UCI_PL, exit_stack
            )
        )

        async with nordvpnlite.start():
            log.debug("NordVPN Lite started, waiting for connected vpn state...")
            await nordvpnlite.wait_for_vpn_connected_state()
            await check_gateway_and_client_ip(
                gateway_connection, client_connection, WG_SERVER["ipv4"]
            )
            logread_proc = await start_logread_process(
                gateway_connection, exit_stack, NETWORK_RESTART_LOG_LINE
            )
        await wait_for_log_line(logread_proc)
        log.info("Network has been reloaded")

        log.debug("Check connection after disconnect from vpn")
        await check_gateway_and_client_ip(
            gateway_connection, client_connection, OPENWRT_GW_WAN_IP
        )

        # uploading config for the second country
        await gateway_connection.upload_file(
            f"data/nordvpnlite/{IfcConfigType.VPN_OPENWRT_UCI_DE.value}",
            f"/etc/nordvpnlite/{IfcConfigType.VPN_OPENWRT_UCI_DE.value}",
        )
        config_path = Paths(exec_path=Path("nordvpnlite"))
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
            logread_proc = await start_logread_process(
                gateway_connection, exit_stack, NETWORK_RESTART_LOG_LINE
            )
        await wait_for_log_line(logread_proc)
        log.info("Network has been reloaded")
