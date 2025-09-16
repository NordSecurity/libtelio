import asyncio
import pytest
from config import PHOTO_ALBUM_IP, STUN_SERVER, WG_SERVER, WG_SERVER_2
from contextlib import AsyncExitStack
from helpers import setup_connections
from nordvpnlite import NordVpnLite, IfcConfigType
from utils import stun
from utils.connection import ConnectionTag
from utils.logger import log
from utils.ping import ping
from utils.process.process import ProcessExecError


@pytest.mark.parametrize(
    "no_detach",
    [True, False],
    ids=["no_detach", "detach"],
)
async def test_nordvpnlite_start(no_detach) -> None:
    async with AsyncExitStack() as exit_stack:
        nordvpnlite = await NordVpnLite.new(exit_stack, no_detach=no_detach)

        with pytest.raises(ProcessExecError) as err:
            await nordvpnlite.quit()
        assert err.value.stderr == "Error: DaemonIsNotRunning"

        async with nordvpnlite.start() as nordvpnlite_client:
            assert await nordvpnlite_client.is_alive()

        with pytest.raises(ProcessExecError) as err:
            await nordvpnlite.quit()
        assert err.value.stderr == "Error: DaemonIsNotRunning"


async def test_nordvpnlite_logs() -> None:
    async with AsyncExitStack() as exit_stack:
        connection = (
            await setup_connections(exit_stack, [ConnectionTag.DOCKER_CONE_CLIENT_1])
        )[0].connection

        nordvpnlite = await NordVpnLite.new(exit_stack, connection=connection)
        async with nordvpnlite.start():
            pass

        expected_log_contents = {
            str(nordvpnlite.config.paths.daemon_log): "task started",
            str(nordvpnlite.config.paths.lib_log): "telio::device",
        }

        # Check if log files exist and are not empty
        done = False
        while not done:
            try:
                for path, expected_string in expected_log_contents.items():
                    await connection.create_process(["test", "-s", path]).execute()
                    await connection.create_process(
                        ["grep", "-q", expected_string, path]
                    ).execute()
                    done = True
            except ProcessExecError:
                await asyncio.sleep(1)


@pytest.mark.parametrize(
    "config_type",
    [(IfcConfigType.MANUAL), (IfcConfigType.IPROUTE)],
)
async def test_nordvpnlite_vpn_connection(config_type: IfcConfigType) -> None:
    async with AsyncExitStack() as exit_stack:
        nordvpnlite = await NordVpnLite.new(exit_stack, config_type)
        await nordvpnlite.request_credentials_from_core()

        async with nordvpnlite.start():
            log.debug("NordVPN Lite started, waiting for connected vpn state...")
            await nordvpnlite.wait_for_vpn_connected_state()

            if config_type == IfcConfigType.MANUAL:
                await exit_stack.enter_async_context(
                    nordvpnlite.setup_interface(vpn_routes=True)
                )

            await ping(nordvpnlite.connection, PHOTO_ALBUM_IP)
            ip = await stun.get(nordvpnlite.connection, STUN_SERVER)
            assert (
                ip == WG_SERVER["ipv4"]
            ), f"wrong public IP when connected to VPN {ip}"


@pytest.mark.parametrize(
    "country",
    [
        (IfcConfigType.VPN_COUNTRY_PL),
        (IfcConfigType.VPN_COUNTRY_DE),
        (IfcConfigType.VPN_COUNTRY_EMPTY),
    ],
)
async def test_nordvpnlite_vpn_country_connection(country: IfcConfigType) -> None:
    async with AsyncExitStack() as exit_stack:
        nordvpnlite = await NordVpnLite.new(exit_stack, country, vpn_public_key=None)
        await nordvpnlite.request_credentials_from_core()

        async with nordvpnlite.start():
            log.debug("NordVPN Lite started, waiting for connected vpn state...")
            await nordvpnlite.wait_for_vpn_connected_state()

            await ping(nordvpnlite.connection, PHOTO_ALBUM_IP)
            ip = await stun.get(nordvpnlite.connection, STUN_SERVER)

            report = await nordvpnlite.get_status()

            if country is not IfcConfigType.VPN_COUNTRY_EMPTY:
                expected_server_ip, expected_hostname = (
                    (WG_SERVER["ipv4"], "pl128.nordvpn.com")
                    if country == IfcConfigType.VPN_COUNTRY_PL
                    else (WG_SERVER_2["ipv4"], "de1263.nordvpn.com")
                )

                assert (
                    ip == expected_server_ip
                ), f"wrong public IP when connected to VPN {ip}"
                assert expected_hostname in report, report
            else:
                assert ip in [
                    WG_SERVER["ipv4"],
                    WG_SERVER_2["ipv4"],
                ], f"wrong public IP when connected to VPN {ip}"
                assert any(
                    hostname in report
                    for hostname in ["pl128.nordvpn.com", "de1263.nordvpn.com"]
                ), report
