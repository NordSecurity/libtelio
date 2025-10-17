import asyncio
import pytest
import re
from config import WG_SERVER, PHOTO_ALBUM_IP, STUN_SERVER, LAN_ADDR_MAP
from contextlib import AsyncExitStack
from helpers import setup_connections
from nordvpnlite import NordVpnLite, Config, IfcConfigType, Paths
from pathlib import Path
from utils import stun
from utils.connection import Connection, ConnectionTag
from utils.connection_util import new_connection_raw
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


async def wait_for_interface_state(
    connection: Connection, interface: str, expected_state: str
) -> bool:
    """
    Wait for an interface state to become up or down.

    Args:
        connection (Connection):
            An active SSH or Docker connection to the OpenWRT gateway.
        interface (str):
            Interface name to check.
        expected_state (str):
            Expected state of the interface - up or down.

    Returns:
        bool
    """
    success = False
    for _ in range(2):
        result = await connection.create_process(
            ["sh", "-c", "ip link show %s | awk '/state/ {print $9}'" % interface]
        ).execute()
        state = result.get_stdout().strip()
        if state == expected_state:
            success = True
            break
        log.debug(
            "Interface %s has state: %s, expected state: %s",
            interface,
            state,
            expected_state,
        )
        await asyncio.sleep(1)
    return success


async def print_network_state(connection: Connection) -> None:
    """
    Print current network state of the OpenWRT gateway.

    Args:
        connection (Connection):
            An active SSH or Docker connection to the OpenWRT gateway.
    Returns:
        None
    """
    ip_a_log = await connection.create_process(["ip", "a"]).execute()
    ip_a = ip_a_log.get_stdout().strip()
    log.debug(
        "--- Log of ip a command ---\n %s",
        ip_a,
    )

    ip_r_log = await connection.create_process(["ip", "r"]).execute()
    ip_r = ip_r_log.get_stdout().strip()
    log.debug(
        "--- Log of ip r command ---\n %s",
        ip_r,
    )

    ip_tables_log = await connection.create_process(["iptables", "-L"]).execute()
    ip_tables = ip_tables_log.get_stdout().strip()
    log.debug(
        "--- Log of iptables -L command ---\n %s",
        ip_tables,
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
        # printing networking state before test execution
        await print_network_state(gateway_connection)

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
        8. Check tcpdump on gateway and client node - all IPs should be vpn ip
    """
    async with AsyncExitStack() as exit_stack:
        client_connection = (
            await setup_connections(exit_stack, [ConnectionTag.DOCKER_OPENWRT_CLIENT_1])
        )[0].connection
        gateway_connection = (
            await setup_connections(exit_stack, [ConnectionTag.VM_OPENWRT_GW_1])
        )[0].connection
        # printing networking state before test execution
        await print_network_state(gateway_connection)
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
                    "10.0.0.0",
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
        client_connection = (
            await setup_connections(exit_stack, [ConnectionTag.DOCKER_OPENWRT_CLIENT_1])
        )[0].connection
        gateway_connection = (
            await setup_connections(exit_stack, [ConnectionTag.VM_OPENWRT_GW_1])
        )[0].connection
        # printing networking state before test execution
        await print_network_state(gateway_connection)

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
