import json
import pytest
from config import PHOTO_ALBUM_IP, STUN_SERVER, WG_SERVER
from contextlib import AsyncExitStack
from helpers import setup_connections
from teliod import Teliod, Config, IfcConfigType
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
    async with AsyncExitStack() as exit_stack:
        teliod = await Teliod.new(exit_stack, config_type)
        node, device_identity = await teliod.register_device_on_core()

        async with teliod.start():
            log.debug("Teliod started, waiting for connected vpn state...")
            await teliod.wait_for_vpn_connected_state()

            if config_type == IfcConfigType.VPN_MANUAL:
                await exit_stack.enter_async_context(
                    teliod.setup_interface(node.ip_addresses, vpn_routes=True)
                )

            await ping(teliod.connection, PHOTO_ALBUM_IP)
            ip = await stun.get(teliod.connection, STUN_SERVER)
            assert (
                ip == WG_SERVER["ipv4"]
            ), f"wrong public IP when connected to VPN {ip}"

            assert device_identity == await teliod.read_identity_file()


async def test_teliod_device_identity_registration() -> None:
    async with AsyncExitStack() as exit_stack:
        teliod = await Teliod.new(exit_stack, IfcConfigType.VPN_IPROUTE_WITHOUT_ID)
        # Device wasn't preregistered on core API like in the previous tests
        # therefore teliod will have to register it.
        async with teliod.start():
            status = await teliod.wait_for_meshnet_ip_on_meshmap()
            device_identity = await teliod.read_identity_file()
            await teliod.whitelist_device_on_the_vpn_servers(
                device_identity, [status["meshnet_ip"]]
            )
            await teliod.wait_for_vpn_connected_state()


async def test_teliod_device_identity_update_when_machine_id_is_missing() -> None:
    async with AsyncExitStack() as exit_stack:
        teliod = await Teliod.new(exit_stack, IfcConfigType.VPN_IPROUTE_WITHOUT_ID)
        _, old_dev_identity = await teliod.register_device_on_core(dump_to_file=False)
        old_machine_id = old_dev_identity.pop("machine_identifier")
        await teliod.write_identity_file(json.dumps(old_dev_identity))

        async with teliod.start():
            status = await teliod.wait_for_meshnet_ip_on_meshmap()
            new_device_identity = await teliod.read_identity_file()

            assert (
                old_dev_identity["hw_identifier"]
                == new_device_identity["hw_identifier"]
            )
            assert old_dev_identity["private_key"] == new_device_identity["private_key"]
            assert old_machine_id == new_device_identity["machine_identifier"]

            await teliod.whitelist_device_on_the_vpn_servers(
                new_device_identity, [status["meshnet_ip"]]
            )
            await teliod.wait_for_vpn_connected_state()


async def test_teliod_device_identity_update_when_keys_are_missing() -> None:
    async with AsyncExitStack() as exit_stack:
        teliod = await Teliod.new(exit_stack, IfcConfigType.VPN_IPROUTE_WITHOUT_ID)
        _, old_dev_identity = await teliod.register_device_on_core(dump_to_file=False)
        old_private_key = old_dev_identity.pop("private_key")
        await teliod.write_identity_file(json.dumps(old_dev_identity))

        async with teliod.start():
            status = await teliod.wait_for_meshnet_ip_on_meshmap()
            new_device_identity = await teliod.read_identity_file()

            assert (
                old_dev_identity["hw_identifier"]
                == new_device_identity["hw_identifier"]
            )
            assert (
                old_dev_identity["machine_identifier"]
                == new_device_identity["machine_identifier"]
            )
            assert old_private_key != new_device_identity["private_key"]

            await teliod.whitelist_device_on_the_vpn_servers(
                new_device_identity, [status["meshnet_ip"]]
            )
            await teliod.wait_for_vpn_connected_state()


async def test_teliod_device_identity_update_when_hw_id_is_missing() -> None:
    async with AsyncExitStack() as exit_stack:
        teliod = await Teliod.new(exit_stack, IfcConfigType.VPN_IPROUTE_WITHOUT_ID)
        _, old_dev_identity = await teliod.register_device_on_core(dump_to_file=False)
        old_hw_identifier = old_dev_identity.pop("hw_identifier")
        await teliod.write_identity_file(json.dumps(old_dev_identity))

        async with teliod.start():
            new_device_identity = await teliod.read_identity_file()

            assert (
                old_dev_identity["machine_identifier"]
                == new_device_identity["machine_identifier"]
            )
            assert old_dev_identity["private_key"] == new_device_identity["private_key"]
            assert old_hw_identifier != new_device_identity["hw_identifier"]

            await teliod.wait_for_vpn_connected_state()
