import asyncio
import base64
import json
import platform
import pytest
import time
import uuid
from config import (
    LIBTELIO_BINARY_PATH_DOCKER,
    WG_SERVER,
    PHOTO_ALBUM_IP,
    STUN_SERVER,
    CORE_API_URL,
    CORE_API_CA_CERTIFICATE_PATH,
    CORE_API_BEARER_AUTHORIZATION_HEADER,
)
from contextlib import AsyncExitStack
from helpers import setup_connections, send_https_request
from mesh_api import API
from utils import stun
from utils.connection import ConnectionTag
from utils.ping import ping
from utils.process.process import ProcessExecError
from utils.router import IPStack
from utils.router.linux_router import LinuxRouter

if platform.machine() != "x86_64":
    import pure_wg as Key
else:
    from python_wireguard import Key  # type: ignore

TELIOD_EXEC_PATH = f"{LIBTELIO_BINARY_PATH_DOCKER}teliod"
CONFIG_FILE_PATH = "/etc/teliod/config.json"
CONFIG_FILE_PATH_WITH_VPN = "/etc/teliod/config_with_vpn.json"
SOCKET_FILE_PATH = "/run/teliod.sock"
STDOUT_FILE_PATH = "/var/log/teliod.log"
LOG_FILE_PATH = "/var/log/teliod_natlab.log"

TELIOD_START_PARAMS = [
    TELIOD_EXEC_PATH,
    "start",
    CONFIG_FILE_PATH,
]

TELIOD_START_NODETACH_PARAMS = [
    TELIOD_EXEC_PATH,
    "start",
    "--no-detach",
    CONFIG_FILE_PATH,
]

TELIOD_STATUS_PARAMS = [TELIOD_EXEC_PATH, "get-status"]
TELIOD_IS_ALIVE_PARAMS = [TELIOD_EXEC_PATH, "is-alive"]
TELIOD_QUIT_DAEMON_PARAMS = [TELIOD_EXEC_PATH, "quit-daemon"]


async def is_teliod_running(connection):
    try:
        await connection.create_process(["test", "-e", SOCKET_FILE_PATH]).execute()
        return True
    except:
        return False


WAIT_FOR_TELIOD_TIMEOUT = 3.0


async def wait_for_teliod(connection):
    start_time = time.monotonic()
    while time.monotonic() - start_time < WAIT_FOR_TELIOD_TIMEOUT:
        try:
            if await asyncio.wait_for(is_teliod_running(connection), 0.5):
                return
        except TimeoutError:
            pass
        await asyncio.sleep(0.1)
    raise TimeoutError("teliod did not start within timeout")


@pytest.mark.parametrize(
    "start_daemon_params",
    [(TELIOD_START_PARAMS), (TELIOD_START_NODETACH_PARAMS)],
    ids=["daemonized_mode", "no_detach_mode"],
)
async def test_teliod(start_daemon_params) -> None:
    async with AsyncExitStack() as exit_stack:
        connection = (
            await setup_connections(exit_stack, [ConnectionTag.DOCKER_CONE_CLIENT_1])
        )[0].connection

        # Run teliod
        await exit_stack.enter_async_context(
            connection.create_process(start_daemon_params).run()
        )

        # Let the daemon start
        await wait_for_teliod(connection)

        with pytest.raises(ProcessExecError) as err:
            await connection.create_process(start_daemon_params).execute()
        assert err.value.stderr == "Error: DaemonIsRunning"

        # Run the get-status command
        assert (
            "telio_is_running"
            in (
                await connection.create_process(TELIOD_STATUS_PARAMS).execute()
            ).get_stdout()
        )

        # Send SIGTERM to the daemon
        await connection.create_process(
            ["killall", "-w", "-s", "SIGTERM", "teliod"]
        ).execute()

        assert not await is_teliod_running(connection)

        # Run the get-status command again - this time it should fail
        with pytest.raises(ProcessExecError) as err:
            await connection.create_process(TELIOD_STATUS_PARAMS).execute()
        assert err.value.stderr == "Error: DaemonIsNotRunning"


@pytest.mark.parametrize(
    "start_daemon_params",
    [(TELIOD_START_PARAMS), (TELIOD_START_NODETACH_PARAMS)],
    ids=["daemonized_mode", "no_detach_mode"],
)
async def test_teliod_quit(start_daemon_params) -> None:
    async with AsyncExitStack() as exit_stack:
        connection = (
            await setup_connections(exit_stack, [ConnectionTag.DOCKER_CONE_CLIENT_1])
        )[0].connection

        # Try to quit deamon that is not running
        with pytest.raises(ProcessExecError) as err:
            await connection.create_process(TELIOD_QUIT_DAEMON_PARAMS).execute()
        assert err.value.stderr == "Error: DaemonIsNotRunning"

        # Run teliod
        await exit_stack.enter_async_context(
            connection.create_process(start_daemon_params).run()
        )

        # Let the daemon start
        await wait_for_teliod(connection)

        # Run the is-alive command
        assert (
            "Command executed successfully"
            in (
                await connection.create_process(TELIOD_IS_ALIVE_PARAMS).execute()
            ).get_stdout()
        )

        # Send quit-daemon command
        assert (
            "Command executed successfully"
            in (
                await connection.create_process(TELIOD_QUIT_DAEMON_PARAMS).execute()
            ).get_stdout()
        )

        assert not await is_teliod_running(connection)

        # Run the is-alive command again - this time it should fail
        with pytest.raises(ProcessExecError) as err:
            await connection.create_process(TELIOD_IS_ALIVE_PARAMS).execute()
        assert err.value.stderr == "Error: DaemonIsNotRunning"


async def test_teliod_logs() -> None:
    async with AsyncExitStack() as exit_stack:
        connection = (
            await setup_connections(exit_stack, [ConnectionTag.DOCKER_CONE_CLIENT_1])
        )[0].connection

        # Delete any old logs
        await connection.create_process(
            ["rm", "-f", STDOUT_FILE_PATH, LOG_FILE_PATH]
        ).execute()

        # Make sure they are indeed deleted
        for path in [STDOUT_FILE_PATH, LOG_FILE_PATH]:
            await connection.create_process(["test", "!", "-f", path]).execute()

        # Run teliod
        await exit_stack.enter_async_context(
            connection.create_process(TELIOD_START_PARAMS).run()
        )

        # Let the daemon start
        await wait_for_teliod(connection)

        # Run the is-alive command
        assert (
            "Command executed successfully"
            in (
                await connection.create_process(TELIOD_IS_ALIVE_PARAMS).execute()
            ).get_stdout()
        )

        # Send quit-daemon command
        assert (
            "Command executed successfully"
            in (
                await connection.create_process(TELIOD_QUIT_DAEMON_PARAMS).execute()
            ).get_stdout()
        )

        assert not await is_teliod_running(connection)

        # expected substrings for each log file
        expected_log_contents = {
            STDOUT_FILE_PATH: "task started",
            LOG_FILE_PATH: "telio::device",
        }

        # Check if log files exist and are not empty
        for path, expected_string in expected_log_contents.items():
            await connection.create_process(["test", "-s", path]).execute()
            await connection.create_process(
                ["grep", "-q", expected_string, path]
            ).execute()


# TODO(LLT-6404): reduce boilerplate
async def test_teliod_vpn_connection_with_manual_interface_setup() -> None:
    async with AsyncExitStack() as exit_stack:
        connection = (
            await setup_connections(exit_stack, [ConnectionTag.DOCKER_CONE_CLIENT_1])
        )[0].connection

        (private_key, public_key) = Key.key_pair()
        hw_identifier = uuid.uuid4()
        payload = {
            "public_key": str(public_key),
            "hardware_identifier": str(hw_identifier),
            "os": "linux",
            "os_version": "teliod",
        }
        response_data = await send_https_request(
            connection,
            f"{CORE_API_URL}/v1/meshnet/machines",
            "POST",
            CORE_API_CA_CERTIFICATE_PATH,
            data=str(payload).replace("'", '"'),
            authorization_header=CORE_API_BEARER_AUTHORIZATION_HEADER,
        )

        device_id = {
            "hw_identifier": str(hw_identifier),
            "private_key": list(base64.b64decode(str(private_key))),
            "machine_identifier": response_data["identifier"],
        }
        await connection.create_process(["mkdir", "-p", "/etc/teliod"]).execute()
        await connection.create_process(
            ["sh", "-c", f"echo '{json.dumps(device_id)}' > /etc/teliod/data.json"]
        ).execute()

        api = API()
        api.register(
            "teliod",
            "teliod",
            str(private_key),
            str(public_key),
            True,
            IPStack.IPv4,
            response_data["ip_addresses"],
        )
        api.prepare_all_vpn_servers()

        # we only know the key of the VPN server at runtime but need it to be in the config before starting teliod
        server_pubkey = WG_SERVER["public_key"]
        await connection.create_process([
            "sed",
            "-i",
            f's#"server_pubkey": .*#"server_pubkey": "{server_pubkey}"#g',
            CONFIG_FILE_PATH_WITH_VPN,
        ]).execute()

        # Run teliod
        start_params = [
            TELIOD_EXEC_PATH,
            "start",
            CONFIG_FILE_PATH_WITH_VPN,
        ]
        await exit_stack.enter_async_context(
            connection.create_process(start_params).run()
        )

        # Let the daemon start
        await wait_for_teliod(connection)

        router = LinuxRouter(connection, IPStack.IPv4)
        router.set_interface_name("teliod")
        await router.setup_interface(response_data["ip_addresses"])
        await router.create_meshnet_route()
        await router.create_vpn_route()

        with pytest.raises(ProcessExecError) as err:
            await connection.create_process(TELIOD_START_PARAMS).execute()
        assert err.value.stderr == "Error: DaemonIsRunning"

        # Run the get-status command
        assert (
            "telio_is_running"
            in (
                await connection.create_process(TELIOD_STATUS_PARAMS).execute()
            ).get_stdout()
        )

        await ping(connection, PHOTO_ALBUM_IP)
        ip = await stun.get(connection, STUN_SERVER)
        assert ip == WG_SERVER["ipv4"], f"wrong public IP when connected to VPN {ip}"

        # Send SIGTERM to the daemon
        await connection.create_process(
            ["killall", "-w", "-s", "SIGTERM", "teliod"]
        ).execute()

        await router.delete_vpn_route()
        await router.delete_exit_node_route()
        await router.delete_interface()

        await connection.create_process([
            "sed",
            "-i",
            's#"server_pubkey": .*#"server_pubkey": "public-key-placeholder"#g',
            CONFIG_FILE_PATH_WITH_VPN,
        ]).execute()

        assert not await is_teliod_running(connection)
