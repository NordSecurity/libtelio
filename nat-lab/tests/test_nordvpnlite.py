import asyncio
import copy
import json
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


async def test_nordvpnlite_connect_when_already_connected() -> None:
    """Calling connect while VPN is already established must return a CLI error
    but must NOT break the existing VPN connection."""
    async with AsyncExitStack() as exit_stack:
        nordvpnlite = await NordVpnLite.new(
            exit_stack,
            config_data=CONFIG_PRESETS[ConfigPresetName.DEFAULT],
        )
        await nordvpnlite.request_credentials_from_core()

        async with nordvpnlite.start():
            log.debug("NordVPN Lite started, waiting for VPN connected state...")
            await nordvpnlite.wait_for_vpn_connected_state()

            status = json.loads(await nordvpnlite.get_status())
            assert (
                status.get("exit_node") is not None
            ), "Expected an active VPN connection"
            assert status["exit_node"]["state"] == "connected", (
                f"Expected exit_node state 'connected', "
                f"got {status['exit_node']['state']!r}"
            )

            log.debug("VPN is connected; sending duplicate connect command...")

            # The second connect must fail with a CLI error.
            try:
                await nordvpnlite.execute_command(["connect"])
                pytest.fail(
                    "Expected a ProcessExecError when calling connect on an "
                    "already-connected VPN, but the command succeeded."
                )
            except ProcessExecError as exc:
                log.debug(
                    "Got expected CLI error on duplicate connect: "
                    "stdout=%r stderr=%r",
                    exc.stdout,
                    exc.stderr,
                )

            log.debug(
                "Duplicate connect raised CLI error; verifying connection is intact..."
            )

            # The daemon must still be running.
            assert (
                await nordvpnlite.is_alive()
            ), "Daemon should still be alive after duplicate connect error"

            # The VPN connection must still be established.
            status = json.loads(await nordvpnlite.get_status())
            assert status.get("exit_node") is not None, (
                "Expected VPN connection to remain active, "
                f"but exit_node={status.get('exit_node')}"
            )
            assert status["exit_node"]["state"] == "connected", (
                f"Expected exit_node state 'connected', "
                f"got {status['exit_node']['state']!r}"
            )

            log.debug("Confirmed: VPN connection intact after duplicate connect")


async def test_nordvpnlite_disconnect_when_not_connected() -> None:
    """Calling disconnect while VPN is not established must return a CLI error
    but the daemon must remain alive."""
    async with AsyncExitStack() as exit_stack:
        nordvpnlite = await NordVpnLite.new(
            exit_stack,
            config_data=CONFIG_PRESETS[ConfigPresetName.DEFAULT],
            do_not_connect=True,
        )

        await nordvpnlite.request_credentials_from_core()

        async with nordvpnlite.start():
            # Daemon is running but VPN connection is NOT established.
            log.debug(
                "NordVPN Lite started with --do-not-connect, "
                "waiting for telio running status..."
            )
            await nordvpnlite.wait_for_telio_running_status()

            assert (
                await nordvpnlite.is_alive()
            ), "Daemon should be alive before disconnect"

            status = json.loads(await nordvpnlite.get_status())
            assert status.get("exit_node") is None, (
                f"Expected no VPN connection before disconnect attempt, "
                f"but exit_node={status.get('exit_node')}"
            )

            log.debug("VPN is not connected; sending disconnect command...")

            # Disconnect must fail with a CLI error since there is nothing to disconnect.
            try:
                await nordvpnlite.execute_command(["disconnect"])
                pytest.fail(
                    "Expected a ProcessExecError when calling disconnect with no "
                    "active VPN connection, but the command succeeded."
                )
            except ProcessExecError as exc:
                log.debug(
                    "Got expected CLI error on disconnect with no connection: "
                    "stdout=%r stderr=%r",
                    exc.stdout,
                    exc.stderr,
                )

            log.debug(
                "Disconnect raised CLI error; verifying daemon is still running..."
            )

            # The daemon must still be running after the failed disconnect.
            assert (
                await nordvpnlite.is_alive()
            ), "Daemon should still be alive after disconnect error"

            log.debug("Confirmed: daemon is still alive after failed disconnect")


async def test_nordvpnlite_reload_preserves_connected_state() -> None:
    """VPN was connected (PL) before reload, after reload stays connected to DE."""
    async with AsyncExitStack() as exit_stack:
        nordvpnlite = await NordVpnLite.new(
            exit_stack,
            config_data=NordVpnLiteConfig(vpn=VPNConfig(country="pl")),
            do_not_connect=True,
        )
        await nordvpnlite.request_credentials_from_core()

        async with nordvpnlite.start():
            await nordvpnlite.wait_for_telio_running_status()
            await nordvpnlite.connect()
            await nordvpnlite.wait_for_vpn_connected_state()

            nordvpnlite.config.config_data = NordVpnLiteConfig(
                vpn=VPNConfig(country="de")
            )
            await nordvpnlite.save_config()
            await nordvpnlite.reload()

            await nordvpnlite.wait_for_vpn_connected_state()
            status = json.loads(await nordvpnlite.get_status())
            assert status.get("exit_node") is not None
            assert status["exit_node"]["state"] == "connected"
            report = await nordvpnlite.get_status()
            assert "de1263.nordvpn.com" in report, report


async def test_nordvpnlite_reload_preserves_disconnected_state() -> None:
    """VPN was disconnected before reload and stays disconnected after reload."""
    async with AsyncExitStack() as exit_stack:
        nordvpnlite = await NordVpnLite.new(
            exit_stack,
            config_data=NordVpnLiteConfig(vpn=VPNConfig(country="pl")),
            do_not_connect=True,
        )
        await nordvpnlite.request_credentials_from_core()

        async with nordvpnlite.start():
            await nordvpnlite.wait_for_telio_running_status()

            nordvpnlite.config.config_data = NordVpnLiteConfig(
                vpn=VPNConfig(country="de")
            )
            await nordvpnlite.save_config()
            await nordvpnlite.reload()

            await nordvpnlite.wait_for_telio_running_status()
            status = json.loads(await nordvpnlite.get_status())
            assert status["telio_is_running"]
            assert status.get("exit_node") is None


async def test_nordvpnlite_connect_disconnect() -> None:
    """Start daemon with --do-not-connect, verify VPN is not established,
    then explicitly connect and disconnect via CLI commands."""
    async with AsyncExitStack() as exit_stack:
        nordvpnlite = await NordVpnLite.new(
            exit_stack,
            config_data=CONFIG_PRESETS[ConfigPresetName.DEFAULT],
            do_not_connect=True,
        )

        await nordvpnlite.request_credentials_from_core()

        async with nordvpnlite.start():
            # Step 1: daemon is running but VPN connection is NOT established
            log.debug(
                "NordVPN Lite started with --do-not-connect, "
                "waiting for telio running status..."
            )
            await nordvpnlite.wait_for_telio_running_status()

            assert await nordvpnlite.is_alive(), "Daemon should be alive"

            status = json.loads(await nordvpnlite.get_status())
            assert status["telio_is_running"], "telio should be running"
            assert (
                status.get("exit_node") is None
            ), f"Expected no VPN connection, but exit_node={status.get('exit_node')}"

            log.debug("Confirmed: daemon running, VPN not connected")

            # Step 2: connect and verify VPN is established
            log.debug("Sending connect command...")
            await nordvpnlite.connect()
            await nordvpnlite.wait_for_vpn_connected_state()

            status = json.loads(await nordvpnlite.get_status())
            assert (
                status.get("exit_node") is not None
            ), "Expected an active VPN exit_node after connect"
            assert status["exit_node"]["state"] == "connected", (
                f"Expected exit_node state 'connected', "
                f"got {status['exit_node']['state']!r}"
            )

            log.debug("Confirmed: VPN connected")

            # Step 3: disconnect and verify VPN connection is stopped
            log.debug("Sending disconnect command...")
            await nordvpnlite.disconnect()
            await nordvpnlite.wait_for_vpn_disconnected_state()

            status = json.loads(await nordvpnlite.get_status())
            assert status.get("exit_node") is None, (
                f"Expected no VPN connection after disconnect, "
                f"but exit_node={status.get('exit_node')}"
            )

            log.debug("Confirmed: VPN disconnected")
