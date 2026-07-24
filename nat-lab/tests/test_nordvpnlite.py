import asyncio
import copy
import pytest
from contextlib import AsyncExitStack
from pathlib import Path
from tests.config import NLX_SERVER, PHOTO_ALBUM_IP, STUN_SERVER, WG_SERVER, WG_SERVER_2
from tests.helpers import setup_connections
from tests.nordvpnlite import (
    NordVpnLite,
    ConfigPresetName,
    CONFIG_PRESETS,
    InterfaceConfig,
    NordVpnLiteConfig,
    VPNConfig,
    VPNServer,
)
from tests.test_pq import inspect_preshared_key
from tests.utils import stun
from tests.utils.connection import ConnectionTag
from tests.utils.connection_util import new_connection_by_tag
from tests.utils.logger import log
from tests.utils.ping import ping
from tests.utils.process.process import ProcessExecError


@pytest.mark.parametrize(
    "no_detach",
    [True, False],
    ids=["no_detach", "detach"],
)
async def test_nordvpnlite_start(no_detach) -> None:
    async with AsyncExitStack() as exit_stack:
        nordvpnlite = await NordVpnLite.new(
            exit_stack,
            config_data=CONFIG_PRESETS[ConfigPresetName.MANUAL],
            no_detach=no_detach,
        )

        await nordvpnlite.kill()

        async with nordvpnlite.start() as nordvpnlite_client:
            assert await nordvpnlite_client.is_alive()

        await nordvpnlite.kill()


async def test_nordvpnlite_logs() -> None:
    async with AsyncExitStack() as exit_stack:
        connection = (
            await setup_connections(exit_stack, [ConnectionTag.DOCKER_CONE_CLIENT_1])
        )[0].connection

        nordvpnlite = await NordVpnLite.new(
            exit_stack,
            config_data=CONFIG_PRESETS[ConfigPresetName.DEFAULT],
            connection=connection,
        )
        async with nordvpnlite.start():
            await nordvpnlite.wait_for_telio_running_status()

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
    "config",
    [
        CONFIG_PRESETS[ConfigPresetName.MANUAL],
        CONFIG_PRESETS[ConfigPresetName.IPROUTE],
    ],
)
async def test_nordvpnlite_vpn_connection(config: NordVpnLiteConfig) -> None:
    async with AsyncExitStack() as exit_stack:
        nordvpnlite = await NordVpnLite.new(exit_stack, config)
        await nordvpnlite.request_credentials_from_core()

        async with nordvpnlite.start():
            log.debug("NordVPN Lite started, waiting for connected vpn state...")
            await nordvpnlite.wait_for_vpn_connected_state()

            if config.interface.config_provider == "manual":
                await exit_stack.enter_async_context(
                    nordvpnlite.setup_interface(vpn_routes=True)
                )

            await ping(nordvpnlite.connection, PHOTO_ALBUM_IP)
            ip = await stun.get(nordvpnlite.connection, STUN_SERVER)
            assert (
                ip == WG_SERVER["ipv4"]
            ), f"wrong public IP when connected to VPN {ip}"


@pytest.mark.parametrize(
    "country_config",
    [
        (NordVpnLiteConfig(vpn=VPNConfig(country="pl"))),
        (NordVpnLiteConfig(vpn=VPNConfig(country="de"))),
        (NordVpnLiteConfig()),
    ],
)
async def test_nordvpnlite_vpn_country_connection(
    country_config: NordVpnLiteConfig,
) -> None:
    async with AsyncExitStack() as exit_stack:
        nordvpnlite = await NordVpnLite.new(exit_stack, country_config)
        await nordvpnlite.request_credentials_from_core()

        async with nordvpnlite.start():
            log.debug("NordVPN Lite started, waiting for connected vpn state...")
            await nordvpnlite.wait_for_vpn_connected_state()

            await ping(nordvpnlite.connection, PHOTO_ALBUM_IP)
            ip = await stun.get(nordvpnlite.connection, STUN_SERVER)

            report = await nordvpnlite.get_status()

            if country_config.vpn is not None:
                expected_server_ip, expected_hostname = (
                    (WG_SERVER["ipv4"], "pl128.nordvpn.com")
                    if country_config.vpn.country == "pl"
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


async def test_nordvpnlite_reload_country_change() -> None:
    async with AsyncExitStack() as exit_stack:
        # Start connected to PL
        initial_config = NordVpnLiteConfig(vpn=VPNConfig(country="pl"))
        nordvpnlite = await NordVpnLite.new(exit_stack, initial_config)
        await nordvpnlite.request_credentials_from_core()

        async with nordvpnlite.start():
            # Verify initial PL connection
            log.debug("Waiting for initial PL VPN connection...")
            await nordvpnlite.wait_for_vpn_connected_state()

            ip = await stun.get(nordvpnlite.connection, STUN_SERVER)
            assert ip == WG_SERVER["ipv4"], f"Expected PL server IP, got {ip}"
            report = await nordvpnlite.get_status()
            assert "pl128.nordvpn.com" in report, report

            # Rewrite config on disk to DE and trigger reload
            log.debug("Updating config to DE and reloading...")
            nordvpnlite.config.config_data = NordVpnLiteConfig(
                vpn=VPNConfig(country="de")
            )
            await nordvpnlite.save_config()
            await nordvpnlite.reload()

            # Verify new DE connection
            log.debug("Waiting for DE VPN connection after reload...")
            await nordvpnlite.wait_for_vpn_connected_state()

            ip = await stun.get(nordvpnlite.connection, STUN_SERVER)
            assert (
                ip == WG_SERVER_2["ipv4"]
            ), f"Expected DE server IP after reload, got {ip}"
            report = await nordvpnlite.get_status()
            assert "de1263.nordvpn.com" in report, report


async def test_nordvpnlite_reload_no_config_change() -> None:
    """Reload without changing the config file should be a no-op (daemon keeps running)."""
    async with AsyncExitStack() as exit_stack:
        config = copy.deepcopy(CONFIG_PRESETS[ConfigPresetName.DEFAULT])
        nordvpnlite = await NordVpnLite.new(exit_stack, config_data=config)

        async with nordvpnlite.start():
            await nordvpnlite.wait_for_telio_running_status()

            # Trigger reload without modifying the config file on disk
            stdout, stderr = await nordvpnlite.execute_command(["reload"])
            assert (
                "Command executed successfully" in stdout
            ), f"Reload command failed: stdout={stdout!r}, stderr={stderr!r}"

            # Force filesystem sync to ensure logs are flushed to disk before checking
            await nordvpnlite.connection.create_process(["sync"]).execute()

            try:
                await nordvpnlite.connection.create_process([
                    "grep",
                    "-q",
                    "Config reloaded, restarting daemon",
                    str(nordvpnlite.config.paths.daemon_log),
                ]).execute()
                pytest.fail("Daemon restarted after reload with unchanged config")
            except ProcessExecError:
                pass  # Expected: restart message absent

            # Daemon must still be alive after the no-op reload
            assert (
                await nordvpnlite.is_alive()
            ), "Daemon is no longer alive after no-op reload"


@pytest.mark.parametrize(
    "config_path",
    [Path("/etc/nordvpnlite/config.json"), Path("/tmp/nordvpnlite/test/config.json")],
    ids=["default", "custom"],
)
async def test_nordvpnlite_config_created(
    config_path: Path, request: pytest.FixtureRequest
) -> None:
    async with AsyncExitStack() as exit_stack:
        connection = (
            await setup_connections(exit_stack, [ConnectionTag.DOCKER_CONE_CLIENT_1])
        )[0].connection

        nordvpnlite = await NordVpnLite.new(
            exit_stack,
            config_data=CONFIG_PRESETS[ConfigPresetName.DEFAULT],
            connection=connection,
        )

        await nordvpnlite.remove_config(config_path)
        assert not await nordvpnlite.config_exists(config_path)

        try:
            if request.node.callspec.id == "default":
                # Start nordvpnlite without a config-file parameter
                await nordvpnlite.execute_command(["daemon"])
            else:
                # Start nordvpnlite with a custom config-file parameter
                await nordvpnlite.execute_command(
                    ["daemon", "--config-file", str(config_path)]
                )
            pytest.fail("Start should not succeed with default config")
        except ProcessExecError as exc:
            assert str(config_path) in exc.stdout, "Config path not mentioned in stdout"
            assert "creating default config" in exc.stdout
            assert "InvalidConfigToken" in exc.stderr
            assert await nordvpnlite.config_exists(
                config_path
            ), "Default config was not created"
        finally:
            await nordvpnlite.remove_config(config_path)


@pytest.mark.nlx
@pytest.mark.parametrize(
    "config_provider",
    ["manual", "iproute"],
)
async def test_nordvpnlite_pq_vpn_connection(config_provider: str) -> None:
    """Verify that nordvpnlite connects to a PQ-capable VPN server using
    post-quantum handshake (mirrors the behaviour exercised by
    ``test_pq.TestPqVpnConnection`` for the libtelio client)."""
    config = NordVpnLiteConfig(
        vpn=VPNConfig(
            server=VPNServer(
                address=str(NLX_SERVER["ipv4"]),
                public_key=str(NLX_SERVER["public_key"]),
            )
        ),
        interface=InterfaceConfig(config_provider=config_provider),
        post_quantum=True,
    )

    async with AsyncExitStack() as exit_stack:
        nordvpnlite = await NordVpnLite.new(exit_stack, config)
        await nordvpnlite.request_credentials_from_core()

        async with nordvpnlite.start():
            log.debug("NordVPN Lite started, waiting for PQ VPN connected state...")
            await nordvpnlite.wait_for_vpn_connected_state()

            if config.interface.config_provider == "manual":
                await exit_stack.enter_async_context(
                    nordvpnlite.setup_interface(vpn_routes=True)
                )

            await ping(nordvpnlite.connection, PHOTO_ALBUM_IP)

            ip = await stun.get(nordvpnlite.connection, STUN_SERVER)
            assert (
                ip == NLX_SERVER["ipv4"]
            ), f"wrong public IP when connected to PQ VPN {ip}"

            # Confirm the PQ handshake actually took place by inspecting the
            # preshared-key slot on the NLX server side — a plain WireGuard
            # connection would leave it unset.
            async with new_connection_by_tag(ConnectionTag.VM_LINUX_NLX_1) as nlx_conn:
                await inspect_preshared_key(nlx_conn)
