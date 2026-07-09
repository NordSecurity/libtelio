import asyncio
import asyncssh
import pytest
import re
from contextlib import AsyncExitStack
from pathlib import Path
from tests.config import (
    WG_SERVER,
    WG_SERVER_2,
    PHOTO_ALBUM_IP,
    STUN_SERVER,
    LAN_ADDR_MAP,
    CORE_API_URL,
)
from tests.helpers import (
    print_network_state,
    wait_for_interface_state,
    wait_for_log_line,
)
from tests.nordvpnlite import (
    NordVpnLite,
    Config,
    ConfigPresetName,
    Paths,
    CONFIG_PRESETS,
)
from tests.timeouts import TEST_OPENWRT_ARMV8_TIMEOUT
from tests.utils import stun
from tests.utils.connection import Connection, ConnectionTag
from tests.utils.connection_util import new_connection_raw, new_connection_by_tag
from tests.utils.logger import log
from tests.utils.openwrt import (
    start_logread_process,
    wait_until_unreachable_after_reboot,
)
from tests.utils.ping import ping
from tests.utils.process import ProcessExecError
from typing import Optional
from urllib.parse import urlparse

NETWORK_RESTART_LOG_LINE = "netifd: Network device 'eth1' link is up"
OPENWRT_GW_WAN_IP = {
    ConnectionTag.VM_OPENWRT_GW_1: "10.0.0.2",
    ConnectionTag.VM_OPENWRT_GW_2: "10.0.0.3",
    ConnectionTag.VM_OPENWRT_GW_3: "10.0.0.4",
}

OPENWRT_TAGS = [
    pytest.param(
        ConnectionTag.DOCKER_OPENWRT_CLIENT_1,
        ConnectionTag.VM_OPENWRT_GW_1,
        id="openwrt-25.12",
    ),
    pytest.param(
        ConnectionTag.DOCKER_OPENWRT_CLIENT_2,
        ConnectionTag.VM_OPENWRT_GW_2,
        id="openwrt-24.10-armv8",
        marks=pytest.mark.timeout(TEST_OPENWRT_ARMV8_TIMEOUT),
    ),
    pytest.param(
        ConnectionTag.DOCKER_OPENWRT_CLIENT_3,
        ConnectionTag.VM_OPENWRT_GW_3,
        id="openwrt-24.10-malta",
    ),
]

OPENWRT_DHCP_TAGS = [
    pytest.param(
        ConnectionTag.DOCKER_OPENWRT_DHCP_CLIENT_1,
        ConnectionTag.VM_OPENWRT_GW_1,
        id="openwrt-25.12",
    ),
    pytest.param(
        ConnectionTag.DOCKER_OPENWRT_DHCP_CLIENT_2,
        ConnectionTag.VM_OPENWRT_GW_2,
        id="openwrt-24.10-armv8",
        marks=pytest.mark.timeout(TEST_OPENWRT_ARMV8_TIMEOUT),
    ),
    pytest.param(
        ConnectionTag.DOCKER_OPENWRT_DHCP_CLIENT_3,
        ConnectionTag.VM_OPENWRT_GW_3,
        id="openwrt-24.10-malta",
    ),
]


async def log_dns_state(connection: Connection) -> None:
    try:
        resolv = await connection.create_process(["cat", "/etc/resolv.conf"]).execute()
        log.info("/etc/resolv.conf:\n%s", resolv.get_stdout())
    except ProcessExecError as e:
        log.info("/etc/resolv.conf not available: %s", e)
    try:
        dnsmasq = await connection.create_process(
            ["sh", "-c", "netstat -ulnp 2>/dev/null | grep :53 || ss -ulnp | grep :53"]
        ).execute()
        log.info("DNS listeners (port 53):\n%s", dnsmasq.get_stdout())
    except ProcessExecError as e:
        log.info("Could not check DNS listeners: %s", e)


async def check_gateway_and_client_ip(
    gateway_connection: Connection,
    client_connection: Connection,
    expected_ip: str | int,
    gw_tag: ConnectionTag = ConnectionTag.VM_OPENWRT_GW_1,
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
        gw_tag (ConnectionTag):
            The connection tag identifying the OpenWRT gateway version,
            used to look up the LuCI UI address.

    Raises:
        AssertionError:
            If either the gateway or the client reports a public IP different from
            `expected_ip` and if LuCi UI isn't available from the client device.
    Returns:
        None
    """
    try:
        # TODO (LLT-6844): Disable strace once problem with ping -9 is resolved
        await ping(gateway_connection, PHOTO_ALBUM_IP, enable_strace=True)
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

    await ping(client_connection, PHOTO_ALBUM_IP, enable_strace=True)
    client_ip = await stun.get(client_connection, STUN_SERVER)
    assert client_ip == expected_ip, (
        f"Client device has wrong public IP when connected to VPN: {client_ip}. "
        f"Expected value: {expected_ip}"
    )
    luci_ui_response = await client_connection.create_process([
        "sh",
        "-c",
        f'curl -s -o /dev/null -w "%{{http_code}}" http://{LAN_ADDR_MAP[gw_tag]["primary"]}/',
    ]).execute()
    luci_ui_response_status = luci_ui_response.get_stdout().strip()
    assert (
        luci_ui_response_status == "200"
    ), f"LuCi UI isn't available. Response status: {luci_ui_response_status}"


async def wait_for_router_dns(
    connection: Connection, host: str, attempts: int = 20, interval: float = 2.0
) -> None:
    """Wait until the OpenWrt router's dnsmasq can resolve `host`.

    After a WAN-down or reboot the router's resolver needs a moment to recover,
    so probe it with a light nslookup before issuing requests that depend on it.
    """
    for attempt in range(1, attempts + 1):
        try:
            await connection.create_process(["nslookup", host], quiet=True).execute()
            return
        except ProcessExecError:
            if attempt == attempts:
                raise
            log.warning(
                "[%s] router cannot resolve %s yet (attempt %d/%d), waiting...",
                connection.tag.name,
                host,
                attempt,
                attempts,
            )
            await asyncio.sleep(interval)


async def setup_openwrt_test_environment(
    country_config: ConfigPresetName,
    exit_stack: AsyncExitStack,
    config_path: Optional[Path] = None,
    auth_path: Optional[Path] = None,
    client_tag: ConnectionTag = ConnectionTag.DOCKER_OPENWRT_CLIENT_1,
    gw_tag: ConnectionTag = ConnectionTag.VM_OPENWRT_GW_1,
) -> tuple[Connection, Connection, NordVpnLite]:
    """
    Set up the OpenWrt test environment.

    This function establishes SSH connections to the OpenWrt gateway and client
    virtual machines, uploads configuration files to the gateway, initializes
    the VpnLite daemon interface for managing the VPN service, and prepares
    mock data for a third-party API used during tests.

    Args:
        country_config (ConfigPresetName):
            Country config for which the OpenWrt environment
            should be configured.
        exit_stack (AsyncExitStack)
        config_path (Optional[Path], optional):
            Custom path to save nordvpnlite config file. Defaults to None.
        client_tag (ConnectionTag):
            The connection tag for the OpenWrt client container.
        gw_tag (ConnectionTag):
            The connection tag for the OpenWrt gateway VM.

    Returns:
        tuple[Connection, Connection, VpnLite]:
            A tuple containing:
            - `client_connection`: connection to the OpenWrt client VM.
            - `gateway_connection`: connection to the OpenWrt gateway VM.
            - `nordvpnlite`: Instance of `NordVpnLite` class used to manage the daemon.
    """
    client_connection = await exit_stack.enter_async_context(
        new_connection_by_tag(client_tag)
    )
    gateway_connection = await exit_stack.enter_async_context(
        new_connection_by_tag(gw_tag)
    )
    # printing networking state before test execution
    await print_network_state(gateway_connection)

    paths = Paths(exec_path=Path("nordvpnlite"))
    config = Config(
        CONFIG_PRESETS[country_config],
        config_path,
        auth_path,
        country_config,
        paths=paths,
    )

    nordvpnlite = NordVpnLite(
        connection=gateway_connection,
        exit_stack=exit_stack,
        config=config,
    )
    # OpenWrt tests exercise router network events (WAN down, reboot); make sure
    # the router's dnsmasq can resolve core-api again before we query it.
    core_api_host = urlparse(CORE_API_URL).hostname or CORE_API_URL
    await wait_for_router_dns(gateway_connection, core_api_host)
    await nordvpnlite.request_credentials_from_core()
    return client_connection, gateway_connection, nordvpnlite


@pytest.mark.asyncio
@pytest.mark.openwrt
@pytest.mark.parametrize("client_tag,gw_tag", OPENWRT_TAGS)
@pytest.mark.parametrize(
    "openwrt_config",
    [
        ConfigPresetName.VPN_OPENWRT_UCI_PL,
    ],
)
async def test_openwrt_vpn_connection(
    openwrt_config: ConfigPresetName,
    client_tag: ConnectionTag,
    gw_tag: ConnectionTag,
) -> None:
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
            await setup_openwrt_test_environment(
                openwrt_config, exit_stack, client_tag=client_tag, gw_tag=gw_tag
            )
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

        async def wait_for_nameserver_lines(expected: int) -> list[str]:
            while True:
                ns_lines = await grep_logread("using nameserver")
                if len(ns_lines) >= expected:
                    return ns_lines
                await asyncio.sleep(1)

        # Restarting the log daemon clears the log. This makes the testcase safe to be execute in any order.
        await gateway_connection.create_process(
            ["/etc/init.d/log", "restart"]
        ).execute()
        await gateway_connection.create_process(
            ["/etc/init.d/dnsmasq", "restart"]
        ).execute()

        ns_lines = await wait_for_nameserver_lines(1)
        assert "daemon.info dnsmasq[1]: using nameserver 10.0.80.82" in ns_lines[0]

        async with nordvpnlite.start():
            log.debug("NordVPN Lite started, waiting for connected vpn state...")
            await nordvpnlite.wait_for_vpn_connected_state()
            await check_gateway_and_client_ip(
                gateway_connection, client_connection, WG_SERVER["ipv4"], gw_tag
            )
            logread_proc = await start_logread_process(
                gateway_connection, exit_stack, NETWORK_RESTART_LOG_LINE
            )
        await wait_for_log_line(logread_proc)
        log.info("Network has been reloaded")

        # check if DHCP DNS nameservers were restored
        ns_lines = await wait_for_nameserver_lines(3)
        assert "daemon.info dnsmasq[1]: using nameserver 10.0.80.82" in ns_lines[0]
        assert "daemon.info dnsmasq[1]: using nameserver 10.0.80.83" in ns_lines[1]
        assert "daemon.info dnsmasq[1]: using nameserver 10.0.80.82" in ns_lines[2]


@pytest.mark.asyncio
@pytest.mark.openwrt
@pytest.mark.parametrize("client_tag,gw_tag", OPENWRT_TAGS)
async def test_openwrt_ip_leaks(
    client_tag: ConnectionTag,
    gw_tag: ConnectionTag,
) -> None:
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
                ConfigPresetName.VPN_OPENWRT_UCI_PL,
                exit_stack,
                client_tag=client_tag,
                gw_tag=gw_tag,
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
                "not arp",
            ]).run() as tcp_dump:
                await ping(gateway_connection, PHOTO_ALBUM_IP, enable_strace=True)
                await ping(client_connection, PHOTO_ALBUM_IP, enable_strace=True)
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
                    OPENWRT_GW_WAN_IP[gw_tag],
                    LAN_ADDR_MAP[client_tag]["primary"],
                    LAN_ADDR_MAP[gw_tag]["primary"],
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
@pytest.mark.parametrize("client_tag,gw_tag", OPENWRT_TAGS)
async def test_openwrt_simulate_network_down(
    client_tag: ConnectionTag,
    gw_tag: ConnectionTag,
) -> None:
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
                ConfigPresetName.VPN_OPENWRT_UCI_PL,
                exit_stack,
                client_tag=client_tag,
                gw_tag=gw_tag,
            )
        )

        async with nordvpnlite.start():
            log.debug("NordVPN Lite started, waiting for connected vpn state...")
            await nordvpnlite.wait_for_vpn_connected_state()
            await check_gateway_and_client_ip(
                gateway_connection, client_connection, WG_SERVER["ipv4"], gw_tag
            )
            # simulating network interface down
            await gateway_connection.create_process(["ifdown", "wan"]).execute()
            if not await wait_for_interface_state(gateway_connection, "eth1", "DOWN"):
                raise RuntimeError("Failed to set interface eth1 DOWN")

            # setting wan interface back
            await gateway_connection.create_process(["ifup", "wan"]).execute()
            if not await wait_for_interface_state(gateway_connection, "eth1", "UP"):
                raise RuntimeError("Failed to set interface eth1 UP")
            # check vpn connection is working after interface is UP
            await check_gateway_and_client_ip(
                gateway_connection, client_connection, WG_SERVER["ipv4"], gw_tag
            )
            logread_proc = await start_logread_process(
                gateway_connection, exit_stack, NETWORK_RESTART_LOG_LINE
            )
        await wait_for_log_line(logread_proc)
        log.info("Network has been reloaded")


@pytest.mark.asyncio
@pytest.mark.openwrt
@pytest.mark.parametrize("client_tag,gw_tag", OPENWRT_TAGS)
async def test_openwrt_vpn_reconnect(
    client_tag: ConnectionTag,
    gw_tag: ConnectionTag,
) -> None:
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
                ConfigPresetName.VPN_OPENWRT_UCI_PL,
                exit_stack,
                client_tag=client_tag,
                gw_tag=gw_tag,
            )
        )

        async with nordvpnlite.start():
            log.debug("NordVPN Lite started, waiting for connected vpn state...")
            await nordvpnlite.wait_for_vpn_connected_state()
            await check_gateway_and_client_ip(
                gateway_connection, client_connection, WG_SERVER["ipv4"], gw_tag
            )
            logread_proc = await start_logread_process(
                gateway_connection, exit_stack, NETWORK_RESTART_LOG_LINE
            )
        await wait_for_log_line(logread_proc)
        log.info("Network has been reloaded")

        log.debug("Check connection after disconnect from vpn")
        await check_gateway_and_client_ip(
            gateway_connection, client_connection, OPENWRT_GW_WAN_IP[gw_tag], gw_tag
        )

        async with nordvpnlite.start():
            log.debug("Reconnect to VPN...")
            await nordvpnlite.wait_for_vpn_connected_state()
            await check_gateway_and_client_ip(
                gateway_connection, client_connection, WG_SERVER["ipv4"], gw_tag
            )
            logread_proc = await start_logread_process(
                gateway_connection, exit_stack, NETWORK_RESTART_LOG_LINE
            )
        await wait_for_log_line(logread_proc)
        log.info("Network has been reloaded")


@pytest.mark.asyncio
@pytest.mark.openwrt
@pytest.mark.parametrize("client_tag,gw_tag", OPENWRT_TAGS)
async def test_openwrt_vpn_reconnect_different_country(
    client_tag: ConnectionTag,
    gw_tag: ConnectionTag,
) -> None:
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
                ConfigPresetName.VPN_OPENWRT_UCI_PL,
                exit_stack,
                client_tag=client_tag,
                gw_tag=gw_tag,
            )
        )

        async with nordvpnlite.start():
            log.debug("NordVPN Lite started, waiting for connected vpn state...")
            await nordvpnlite.wait_for_vpn_connected_state()
            await check_gateway_and_client_ip(
                gateway_connection, client_connection, WG_SERVER["ipv4"], gw_tag
            )
            logread_proc = await start_logread_process(
                gateway_connection, exit_stack, NETWORK_RESTART_LOG_LINE
            )
        await wait_for_log_line(logread_proc)
        log.info("Network has been reloaded")

        log.debug("Check connection after disconnect from vpn")
        await check_gateway_and_client_ip(
            gateway_connection, client_connection, OPENWRT_GW_WAN_IP[gw_tag], gw_tag
        )

        config_path = Paths(exec_path=Path("nordvpnlite"))
        nordvpnlite_de = NordVpnLite(
            gateway_connection,
            exit_stack,
            config=Config(
                CONFIG_PRESETS[ConfigPresetName.VPN_OPENWRT_UCI_DE],
                config_name=ConfigPresetName.VPN_OPENWRT_UCI_DE,
                paths=config_path,
            ),
        )
        async with nordvpnlite_de.start():
            log.debug("Reconnect to VPN DE...")
            await nordvpnlite_de.wait_for_vpn_connected_state()
            await check_gateway_and_client_ip(
                gateway_connection, client_connection, WG_SERVER_2["ipv4"], gw_tag
            )
            logread_proc = await start_logread_process(
                gateway_connection, exit_stack, NETWORK_RESTART_LOG_LINE
            )
        await wait_for_log_line(logread_proc)
        log.info("Network has been reloaded")


@pytest.mark.asyncio
@pytest.mark.openwrt
@pytest.mark.parametrize("client_tag,gw_tag", OPENWRT_TAGS)
async def test_openwrt_router_restart(
    client_tag: ConnectionTag,
    gw_tag: ConnectionTag,
) -> None:
    """
    Check vpn connection is restored after OpenWRT router restart

    Steps:
        1. Prepare vpn servers
        2. Send post request to core-api to save public key of vpn server we are planning to use
        3. Start NordVPN Lite in OpenWRT container
        4. Check ip address of OpenWrt router is equal to vpn ip address
        5. Reboot OpenWrt router
        6. Wait for router to get back online
        7. Check ip address of OpenWrt router and client is equal to vpn ip address
        8. Ping PHOTO_ALBUM_IP from both openwrt and client node
    """
    # wrapping into try/except as there will be connection loss after reboot
    try:
        async with AsyncExitStack() as exit_stack:
            # setting up openwrt environment
            # In reboot scenario we need to use default config path as
            # /etc/nordvpnlite/config.json is persisted across reboots
            client_connection, gateway_connection, nordvpnlite = (
                await setup_openwrt_test_environment(
                    ConfigPresetName.VPN_OPENWRT_UCI_PL,
                    exit_stack,
                    config_path=Path("/etc/nordvpnlite/config.json"),
                    auth_path=Path("/etc/nordvpnlite/auth.json"),
                    client_tag=client_tag,
                    gw_tag=gw_tag,
                )
            )
            await gateway_connection.create_process(
                ["mkdir", "-p", "/etc/nordvpnlite"]
            ).execute()

            # start nordvpnlite without a cleanup as we want to validate vpn connection restore
            async with nordvpnlite.start(cleanup=False):
                log.debug("NordVPN Lite started, waiting for connected vpn state...")
                await nordvpnlite.wait_for_vpn_connected_state()
                await check_gateway_and_client_ip(
                    gateway_connection, client_connection, WG_SERVER["ipv4"], gw_tag
                )
                await exit_stack.enter_async_context(
                    gateway_connection.create_process(["reboot"]).run()
                )
                await wait_until_unreachable_after_reboot(gateway_connection)
    except (
        asyncssh.misc.ConnectionLost,
        asyncssh.misc.ChannelOpenError,
        asyncssh.misc.DisconnectError,
        OSError,
        asyncio.TimeoutError,
    ) as e:
        log.info("Caught exception during reboot: %s: %s", type(e).__name__, e)
        log.info("Connection lost during teardown — expected after reboot")
    async with AsyncExitStack() as exit_stack:
        gateway_connection_after_reboot = None

        client_connection = await exit_stack.enter_async_context(
            new_connection_by_tag(client_tag)
        )

        while True:
            try:
                gateway_connection_after_reboot = await exit_stack.enter_async_context(
                    new_connection_by_tag(gw_tag)
                )
                break
            except Exception as e:  # pylint: disable=broad-exception-caught
                log.debug("OpenWrt router is still rebooting")
                log.debug(e)
                await asyncio.sleep(15)
        assert (
            gateway_connection_after_reboot is not None
        ), "OpenWrt router didn't get back online after reboot"
        log.info("Established new connection to the OpenWrt router")
        await log_dns_state(gateway_connection_after_reboot)
        config_path = Paths(exec_path=Path("nordvpnlite"))
        nordvpnlite_after_reboot = NordVpnLite(
            gateway_connection_after_reboot,
            exit_stack,
            config=Config(CONFIG_PRESETS[ConfigPresetName.DEFAULT], paths=config_path),
        )
        # wrap into try/finally to always execute cleanup code
        try:
            log.info("wait for vpn connection to be re-established after reboot")
            await log_dns_state(gateway_connection_after_reboot)
            await nordvpnlite_after_reboot.wait_for_nordvpnlite_start()
            await nordvpnlite_after_reboot.wait_for_vpn_connected_state()
            await check_gateway_and_client_ip(
                gateway_connection_after_reboot,
                client_connection,
                WG_SERVER["ipv4"],
                gw_tag,
            )
        finally:
            logread_proc = await start_logread_process(
                gateway_connection_after_reboot, exit_stack, NETWORK_RESTART_LOG_LINE
            )
            log.info("Stop nordvpnlite with init script to disable auto reconnect")
            await gateway_connection_after_reboot.create_process(
                ["/etc/init.d/nordvpnlite", "stop"]
            ).execute()
            await nordvpnlite_after_reboot.clean_up()
            await wait_for_log_line(logread_proc)
            log.info("Network has been reloaded")


async def get_client_mtu(client_connection: Connection, interface: str = "eth0") -> int:
    """Return the kernel MTU of the given client interface."""
    proc = await client_connection.create_process(
        ["cat", f"/sys/class/net/{interface}/mtu"]
    ).execute()
    return int(proc.get_stdout().strip())


async def renew_dhcp_lease(
    client_connection: Connection, interface: str = "eth0"
) -> None:
    """
    Re-request the DHCP lease so the client applies whatever the gateway currently advertises.
    The udhcpc hook (bin/udhcpc.script) sets the interface MTU from DHCP option 26, or resets it to
    1500 when the option is absent - so a renew reflects the VPN connect/disconnect state directly.
    `-O mtu` makes udhcpc request option 26 in the parameter request list (as dhclient and
    NetworkManager do); dnsmasq only sends the option when it is requested.
    """
    await client_connection.create_process([
        "busybox",
        "udhcpc",
        "-i",
        interface,
        "-n",
        "-q",
        "-t",
        "10",
        "-O",
        "mtu",
        "-s",
        "/opt/bin/udhcpc.script",
    ]).execute()


@pytest.mark.asyncio
@pytest.mark.openwrt
@pytest.mark.parametrize("client_tag,gw_tag", OPENWRT_DHCP_TAGS)
@pytest.mark.parametrize(
    "openwrt_config",
    [
        ConfigPresetName.VPN_OPENWRT_UCI_PL,
    ],
)
async def test_openwrt_dhcp_client_gets_vpn_mtu(
    openwrt_config: ConfigPresetName,
    client_tag: ConnectionTag,
    gw_tag: ConnectionTag,
) -> None:
    """
    A DHCP LAN client behind the OpenWRT router must receive the VPN-adjusted MTU (LLT-6852).

    With the VPN connected, traffic towards the outside network has to fit within the WireGuard
    overhead (~80 B), so the router advertises MTU 1420 to LAN clients via DHCP option 26
    (interface-mtu). A DHCP client picks this up and lowers its interface MTU to 1420; with the
    VPN disconnected it returns to 1500.

    Runs on each OpenWRT gateway version with its dedicated DHCP client (`nat-lab:dhcp-client`).

    Steps:
        1. Set up the OpenWRT gateway with nordvpnlite and the DHCP client.
        2. Before connecting, the client MTU is 1500.
        3. Connect to the VPN, renew the lease -> the client MTU is 1420.
        4. Disconnect, renew the lease -> the client MTU is back to 1500.
    """
    async with AsyncExitStack() as exit_stack:
        client_connection, gateway_connection, nordvpnlite = (
            await setup_openwrt_test_environment(
                openwrt_config,
                exit_stack,
                client_tag=client_tag,
                gw_tag=gw_tag,
            )
        )

        # Baseline: with no VPN, the client must use the standard 1500 MTU.
        await renew_dhcp_lease(client_connection)
        baseline_mtu = await get_client_mtu(client_connection)
        assert (
            baseline_mtu == 1500
        ), f"Expected client MTU 1500 before the VPN is connected, got {baseline_mtu}"

        async with nordvpnlite.start():
            log.debug("NordVPN Lite started, waiting for connected vpn state...")
            await nordvpnlite.wait_for_vpn_connected_state()

            await renew_dhcp_lease(client_connection)
            connected_mtu = await get_client_mtu(client_connection)
            assert connected_mtu == 1420, (
                "Client must pick up the VPN MTU advertised over DHCP (option 26) while connected;"
                f" expected 1420, got {connected_mtu}"
            )

            logread_proc = await start_logread_process(
                gateway_connection, exit_stack, NETWORK_RESTART_LOG_LINE
            )
        await wait_for_log_line(logread_proc)
        log.info("Network has been reloaded")

        # After disconnect, the option is no longer advertised -> client returns to 1500.
        await renew_dhcp_lease(client_connection)
        restored_mtu = await get_client_mtu(client_connection)
        assert (
            restored_mtu == 1500
        ), f"Client MTU must return to 1500 after disconnecting from the VPN, got {restored_mtu}"


@pytest.mark.asyncio
@pytest.mark.openwrt
@pytest.mark.parametrize(
    "openwrt_config",
    [
        ConfigPresetName.VPN_OPENWRT_UCI_PL,
    ],
)
async def test_openwrt_dhcp_client_restores_existing_mtu(
    openwrt_config: ConfigPresetName,
) -> None:
    """
    When the LAN already advertises a higher MTU via DHCP option 26, connecting the VPN must
    override it with the VPN MTU (1420) and disconnecting must restore the original value (LLT-6852).

    Runs on the 25.12 gateway with the dedicated DHCP client; the restore logic does not depend
    on the OpenWRT version.

    Steps:
        1. Pre-seed the gateway LAN with its own DHCP option 26 (MTU 1480) before nordvpnlite starts.
        2. The client picks up 1480.
        3. Connect to the VPN, renew the lease -> the client MTU is overridden to the VPN MTU 1420.
        4. Disconnect, renew the lease -> the client MTU is back to the original 1480.
    """
    preexisting_mtu = 1480
    async with AsyncExitStack() as exit_stack:
        client_connection, gateway_connection, nordvpnlite = (
            await setup_openwrt_test_environment(
                openwrt_config,
                exit_stack,
                client_tag=ConnectionTag.DOCKER_OPENWRT_DHCP_CLIENT_1,
                gw_tag=ConnectionTag.VM_OPENWRT_GW_1,
            )
        )

        async def reload_gateway_dhcp() -> None:
            await gateway_connection.create_process(["uci", "commit", "dhcp"]).execute()
            await gateway_connection.create_process(
                ["/etc/init.d/dnsmasq", "reload"]
            ).execute()

        async def clear_gateway_dhcp_option() -> None:
            await gateway_connection.create_process(
                ["uci", "-q", "delete", "dhcp.lan.dhcp_option"]
            ).execute()
            await reload_gateway_dhcp()

        # Pre-seed the gateway's own option 26 before nordvpnlite starts; remove it on teardown.
        exit_stack.push_async_callback(clear_gateway_dhcp_option)
        await gateway_connection.create_process(
            ["uci", "add_list", f"dhcp.lan.dhcp_option=26,{preexisting_mtu}"]
        ).execute()
        await reload_gateway_dhcp()

        # Baseline: the client picks up the gateway's own MTU.
        await renew_dhcp_lease(client_connection)
        baseline_mtu = await get_client_mtu(client_connection)
        assert (
            baseline_mtu == preexisting_mtu
        ), f"Expected the gateway's own MTU {preexisting_mtu} before connecting, got {baseline_mtu}"

        async with nordvpnlite.start():
            log.debug("NordVPN Lite started, waiting for connected vpn state...")
            await nordvpnlite.wait_for_vpn_connected_state()

            await renew_dhcp_lease(client_connection)
            connected_mtu = await get_client_mtu(client_connection)
            assert connected_mtu == 1420, (
                "VPN MTU must override the gateway's own option 26 with 1420 while connected;"
                f" expected 1420, got {connected_mtu}"
            )

            logread_proc = await start_logread_process(
                gateway_connection, exit_stack, NETWORK_RESTART_LOG_LINE
            )
        await wait_for_log_line(logread_proc)
        log.info("Network has been reloaded")

        # After disconnect, the gateway's original option 26 must be restored.
        await renew_dhcp_lease(client_connection)
        restored_mtu = await get_client_mtu(client_connection)
        assert (
            restored_mtu == preexisting_mtu
        ), f"Original MTU {preexisting_mtu} must be restored after disconnect, got {restored_mtu}"


@pytest.mark.asyncio
@pytest.mark.openwrt
@pytest.mark.parametrize(
    "openwrt_config",
    [
        ConfigPresetName.VPN_OPENWRT_UCI_PL,
    ],
)
async def test_openwrt_dhcp_client_mtu_derived_from_wan(
    openwrt_config: ConfigPresetName,
) -> None:
    """
    The advertised MTU is derived from the underlying WAN interface that reaches the VPN server,
    as min(wan_mtu, 1500) - 80, not a hardcoded 1420 (LLT-6852). On a sub-1500 WAN the LAN client
    must receive the smaller, correct value.

    Runs on the 25.12 gateway; the derivation does not depend on the OpenWRT version.

    Steps:
        1. Lower the gateway's WAN (default-route) interface MTU before nordvpnlite starts.
        2. Connect to the VPN, renew the lease -> the client MTU is wan_mtu - 80.
        3. Teardown restores the WAN interface MTU.
    """
    wan_mtu = 1400
    expected_client_mtu = wan_mtu - 80  # WireGuard overhead
    async with AsyncExitStack() as exit_stack:
        client_connection, gateway_connection, nordvpnlite = (
            await setup_openwrt_test_environment(
                openwrt_config,
                exit_stack,
                client_tag=ConnectionTag.DOCKER_OPENWRT_DHCP_CLIENT_1,
                gw_tag=ConnectionTag.VM_OPENWRT_GW_1,
            )
        )

        # The gateway's WAN is its default-route interface - the same one nordvpnlite reads.
        route = (
            await gateway_connection.create_process(
                ["ip", "route", "show", "default"]
            ).execute()
        ).get_stdout()
        fields = route.splitlines()[0].split()
        wan_iface = fields[fields.index("dev") + 1]
        original_wan_mtu = await get_client_mtu(gateway_connection, wan_iface)

        async def restore_wan_mtu() -> None:
            await gateway_connection.create_process(
                ["ip", "link", "set", "dev", wan_iface, "mtu", str(original_wan_mtu)]
            ).execute()

        # Lower the WAN MTU before nordvpnlite starts, so it reads the reduced value at startup.
        exit_stack.push_async_callback(restore_wan_mtu)
        await gateway_connection.create_process(
            ["ip", "link", "set", "dev", wan_iface, "mtu", str(wan_mtu)]
        ).execute()

        async with nordvpnlite.start():
            log.debug("NordVPN Lite started, waiting for connected vpn state...")
            await nordvpnlite.wait_for_vpn_connected_state()

            await renew_dhcp_lease(client_connection)
            connected_mtu = await get_client_mtu(client_connection)
            assert connected_mtu == expected_client_mtu, (
                f"Advertised MTU must be derived from the {wan_mtu} WAN interface as"
                f" {expected_client_mtu} (wan - 80), got {connected_mtu}"
            )
