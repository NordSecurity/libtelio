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
        node, _ = await teliod.register_device_on_core()

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


# TODO: Blocked by LLT-6406, when teliod registers the machine it doesn't configure
# the interface with the updated meshmap retrieved from the API.
#
# async def test_teliod_device_identity_registration() -> None:
#     async with AsyncExitStack() as exit_stack:
#         teliod = await Teliod.new(exit_stack, IfcConfigType.VPN_IPROUTE_WITHOUT_ID)

#         # Device wasn't preregistered on core API like in the previous tests
#         # therefore teliod will be forced to register it.
#         async with teliod.start():
#             await teliod.wait_for_vpn_connected_state()


# async def test_teliod_device_identity_update_when_not_matching() -> None:
#     async with AsyncExitStack() as exit_stack:
#         teliod = await Teliod.new(exit_stack, IfcConfigType.VPN_IPROUTE_WITHOUT_ID)
#         node, dev_id = await teliod.register_device_on_core(dump_to_file=False)
#         dev_id.pop("machine_identifier")
#         await teliod.write_identity_file(json.dumps(dev_id))

#         async with teliod.start():
#             await teliod.wait_for_vpn_connected_state()


# async def test_teliod_device_identity_update_without_keys() -> None:
#     async with AsyncExitStack() as exit_stack:
#         teliod = await Teliod.new(exit_stack, IfcConfigType.VPN_IPROUTE_WITHOUT_ID)
#         node, dev_id = await teliod.register_device_on_core(dump_to_file=False)
#         dev_id.pop("private_key")
#         await teliod.write_identity_file(json.dumps(dev_id))

#         async with teliod.start():
#             await teliod.wait_for_vpn_connected_state()


# async def test_teliod_device_identity_update_without_hw_id() -> None:
#     async with AsyncExitStack() as exit_stack:
#         teliod = await Teliod.new(exit_stack, IfcConfigType.VPN_IPROUTE_WITHOUT_ID)
#         node, dev_id = await teliod.register_device_on_core(dump_to_file=False)
#         dev_id.pop("hw_identifier")
#         await teliod.write_identity_file(json.dumps(dev_id))

#         async with teliod.start():
#             await teliod.wait_for_vpn_connected_state()
