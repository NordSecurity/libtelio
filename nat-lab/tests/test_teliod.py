import base64
import json
import platform
import pytest
import uuid
from config import (
    WG_SERVER,
    PHOTO_ALBUM_IP,
    STUN_SERVER,
    CORE_API_URL,
    CORE_API_CA_CERTIFICATE_PATH,
    CORE_API_BEARER_AUTHORIZATION_HEADER,
)
from contextlib import AsyncExitStack
from helpers import setup_connections, send_https_request
from mesh_api import API, Node
from teliod import Teliod, Config, IfcConfigType
from utils import stun
from utils.connection import ConnectionTag
from utils.logger import log
from utils.ping import ping
from utils.process.process import ProcessExecError
from utils.router import IPStack
from utils.router.linux_router import LinuxRouter

if platform.machine() != "x86_64":
    import pure_wg as Key
else:
    from python_wireguard import Key  # type: ignore


@pytest.mark.parametrize(
    "no_detach",
    [True, False],
    ids=["no_detach", "detach"],
)
async def test_teliod_start(no_detach) -> None:
    async with AsyncExitStack() as exit_stack:
        connection = (
            await setup_connections(exit_stack, [ConnectionTag.DOCKER_CONE_CLIENT_1])
        )[0].connection

        teliod = Teliod(connection, exit_stack, Config(no_detach=no_detach))

        with pytest.raises(ProcessExecError) as err:
            await teliod.quit()
        assert err.value.stderr == "Error: DaemonIsNotRunning"

        async with teliod.start() as teliod_client:
            assert await teliod_client.is_alive()

        with pytest.raises(ProcessExecError) as err:
            await teliod.quit()
        assert err.value.stderr == "Error: DaemonIsNotRunning"


async def test_teliod_logs() -> None:
    async with AsyncExitStack() as exit_stack:
        connection = (
            await setup_connections(exit_stack, [ConnectionTag.DOCKER_CONE_CLIENT_1])
        )[0].connection

        teliod = Teliod(connection, exit_stack)

        async with teliod.start():
            pass

        expected_log_contents = {
            str(teliod.config.paths.daemon_log): "task started",
            str(teliod.config.paths.lib_log): "telio::device",
        }

        # Check if log files exist and are not empty
        for path, expected_string in expected_log_contents.items():
            await connection.create_process(["test", "-s", path]).execute()
            await connection.create_process(
                ["grep", "-q", expected_string, path]
            ).execute()


@pytest.mark.parametrize(
    "config_type",
    [(IfcConfigType.VPN_MANUAL), (IfcConfigType.VPN_IPROUTE)],
)
async def test_teliod_vpn_connection(config_type: IfcConfigType) -> None:
    async def register_new_device_on_api():
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

        device_id_json = json.dumps(device_id)
        log.debug("Device ID: %s", device_id_json)

        await connection.create_process(["mkdir", "-p", "/etc/teliod"]).execute()
        await connection.create_process(
            ["sh", "-c", f"echo '{device_id_json}' > /etc/teliod/data.json"]
        ).execute()

        api = API()
        node: Node = api.register(
            "teliod",
            "teliod",
            str(private_key),
            str(public_key),
            True,
            IPStack.IPv4,
            response_data["ip_addresses"],
        )
        api.prepare_all_vpn_servers()

        return node

    async with AsyncExitStack() as exit_stack:
        connection = (
            await setup_connections(exit_stack, [ConnectionTag.DOCKER_CONE_CLIENT_1])
        )[0].connection

        teliod = Teliod(connection, exit_stack, config=Config(config_type))

        node: Node = await register_new_device_on_api()

        # we only know the key of the VPN server at runtime and it needs to be in the config before starting teliod
        await connection.create_process([
            "sed",
            "-i",
            f's#"server_pubkey": .*#"server_pubkey": "{WG_SERVER["public_key"]}"#g',
            str(teliod.config.path()),
        ]).execute()

        async with teliod.start():
            log.debug("Teliod started, waiting for connected vpn state...")
            await teliod.wait_for_vpn_connected_state()

            router = LinuxRouter(connection, IPStack.IPv4)
            if config_type == IfcConfigType.VPN_MANUAL:
                router.set_interface_name("teliod")
                await router.setup_interface(node.ip_addresses)
                await router.create_meshnet_route()
                await router.create_vpn_route()

            await ping(connection, PHOTO_ALBUM_IP)
            ip = await stun.get(connection, STUN_SERVER)
            assert (
                ip == WG_SERVER["ipv4"]
            ), f"wrong public IP when connected to VPN {ip}"

            if config_type == ConfigType.VPN_MANUAL:
                await router.delete_vpn_route()
                await router.delete_exit_node_route()
                await router.delete_interface()

            await connection.create_process([
                "sed",
                "-i",
                's#"server_pubkey": .*#"server_pubkey": "public-key-placeholder"#g',
                str(teliod.config.path()),
            ]).execute()
