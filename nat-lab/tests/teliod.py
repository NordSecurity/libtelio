import asyncio
import base64
import json
import os
import platform
import re
import time
import uuid
from config import (
    LIBTELIO_BINARY_PATH_DOCKER,
    CORE_API_URL,
    CORE_API_CA_CERTIFICATE_PATH,
    CORE_API_BEARER_AUTHORIZATION_HEADER,
    WG_SERVER,
)
from contextlib import AsyncExitStack, asynccontextmanager
from dataclasses import dataclass
from enum import Enum
from helpers import send_https_request, setup_connections
from mesh_api import API, Node
from pathlib import Path
from test_core_api import clean_up_machines as clean_up_registered_machines_on_api
from typing import Any, AsyncIterator, Dict, List, Optional
from uniffi.telio_bindings import generate_public_key
from utils.connection import Connection, ConnectionTag
from utils.logger import log
from utils.process import Process, ProcessExecError
from utils.router import IPStack
from utils.router.linux_router import LinuxRouter

if platform.machine() != "x86_64":
    import pure_wg as Key
else:
    from python_wireguard import Key  # type: ignore


class TeliodObtainingIdentity(Exception):
    pass


class IfcConfigType(Enum):
    DEFAULT = "config.json"
    VPN_MANUAL = "config_with_vpn_manual_setup.json"
    VPN_IPROUTE = "config_with_vpn_iproute_setup.json"
    VPN_IPROUTE_WITHOUT_ID = "config_with_vpn_iproute_without_id_file.json"


@dataclass(frozen=True)
class Paths:
    exec_path: Path = Path(f"{LIBTELIO_BINARY_PATH_DOCKER}/teliod")
    config_dir: Path = Path("/etc/teliod")
    local_data_dir: Path = Path("/root/.local/share")
    log_dir: Path = Path("/var/log")
    run_dir: Path = Path("/run")

    def __post_init__(self):
        if os.environ.get("PYTEST_CURRENT_TEST"):
            if not self.exec_path.exists():
                raise FileNotFoundError(
                    f"Teliod executable not found: {self.exec_path}"
                )

    @property
    def socket_file(self) -> Path:
        return self.run_dir / "teliod.sock"

    @property
    def daemon_log(self) -> Path:
        return self.log_dir / "teliod.log"

    @property
    def lib_log(self) -> Path:
        return self.log_dir / "teliod_natlab.log"

    @property
    def teliod_local_data_dir(self) -> Path:
        return self.local_data_dir / "teliod"

    def config_path(self, config_type: IfcConfigType = IfcConfigType.DEFAULT) -> Path:
        return self.config_dir / config_type.value

    def device_identity_path(self) -> Path:
        return self.teliod_local_data_dir / "data.json"


class Command(list):
    def __str__(self) -> str:
        return " ".join(str(item) for item in self)

    def __repr__(self) -> str:
        return f"Command({super().__repr__()})"

    @classmethod
    def start(cls, config: "Config") -> "Command":
        cmd = [str(Paths.exec_path), "start"]
        if config.no_detach:
            cmd.append("--no-detach")
        cmd.append(str(config.path()))
        return cls(cmd)

    @classmethod
    def is_alive(cls) -> "Command":
        return cls([str(Paths.exec_path), "is-alive"])

    @classmethod
    def get_status(cls) -> "Command":
        return cls([str(Paths.exec_path), "get-status"])

    @classmethod
    def quit_daemon(cls) -> "Command":
        return cls([str(Paths.exec_path), "quit-daemon"])


class Config:
    def __init__(
        self,
        config_type: IfcConfigType = IfcConfigType.DEFAULT,
        no_detach: bool = False,
        paths=Paths(),
    ):
        self.paths: Paths = paths
        self.config_type: IfcConfigType = config_type
        self.no_detach: bool = no_detach

    def path(self) -> Path:
        return self.paths.config_path(self.config_type)

    async def assert_match_daemon_start(self, stdout: str):
        assert (
            "Starting daemon" in stdout
        ), f"Could not find 'Starting daemon' in: '{stdout}'"

        config_match = re.search(r"Reading config from:\s*(.+.json)", stdout)
        assert config_match, f"Could not find config path in: {stdout}"
        config_path = Path(config_match.group(1).strip())
        assert (
            config_path == self.path()
        ), f"Config path does not match: '{config_path}' != '{self.path()}'"

        log_match = re.search(r"Saving logs to:\s*(.+\.log)", stdout)
        assert log_match, f"Could not find log path in: {stdout}"
        log_path = Path(log_match.group(1).strip())
        assert (
            log_path == self.paths.lib_log
        ), f"Log path does not match: '{log_path}' != '{self.paths.lib_log}'"

        return config_path, log_path


class Teliod:
    START_TIMEOUT_S = 3
    SOCKET_CHECK_INTERVAL_S = 0.5
    TELIOD_CMD_CHECK_INTERVAL_S = 1

    def __init__(
        self,
        connection: Connection,
        exit_stack: AsyncExitStack,
        config: Config = Config(),
        api: Optional[API] = None,
    ) -> None:
        self._api: API = api if api is not None else API()
        self._exit_stack: AsyncExitStack = exit_stack
        self.connection: Connection = connection
        self.config: Config = config

    @classmethod
    async def new(
        cls, exit_stack: AsyncExitStack, config_type: IfcConfigType
    ) -> "Teliod":
        connection = (
            await setup_connections(exit_stack, [ConnectionTag.DOCKER_CONE_CLIENT_1])
        )[0].connection
        await clean_up_registered_machines_on_api(connection, CORE_API_URL)

        teliod = cls(connection, exit_stack, config=Config(config_type))

        # VPN server keys are generated only at runtime.
        if config_type in [
            IfcConfigType.VPN_IPROUTE,
            IfcConfigType.VPN_MANUAL,
            IfcConfigType.VPN_IPROUTE_WITHOUT_ID,
        ]:
            await exit_stack.enter_async_context(
                teliod.setup_vpn_public_key(str(WG_SERVER["public_key"]))
            )

        return teliod

    async def execute_command(
        self,
        cmd: Command,
    ) -> tuple[str, str]:
        try:
            proc = await self.connection.create_process(cmd).execute()
            stdout, stderr = proc.get_stdout(), proc.get_stderr()
            log.debug("'%s' stdout: '%s', stderr: '%s'", cmd, stdout, stderr)
            return stdout, stderr
        except ProcessExecError as exc:
            log.debug("Exception occured while executing teliod command: %s", exc)
            raise

    async def run_command(
        self,
        cmd: Command,
    ) -> Process:
        proc = await self._exit_stack.enter_async_context(
            self.connection.create_process(cmd).run()
        )
        return proc

    @asynccontextmanager
    async def start(self) -> AsyncIterator["Teliod"]:
        try:
            await self.remove_logs()

            async def wait_for_teliod_start():
                await self.wait_for_teliod_socket()
                while True:
                    try:
                        if not await self.is_alive():
                            raise RuntimeError(
                                "socket exists but daemon's not running."
                            )
                        break
                    except TeliodObtainingIdentity:
                        await asyncio.sleep(self.TELIOD_CMD_CHECK_INTERVAL_S)
                        continue

            if not self.config.no_detach:
                stdout, stderr = await self.execute_command(Command.start(self.config))
                await wait_for_teliod_start()
            else:
                proc = await self.run_command(Command.start(self.config))
                await wait_for_teliod_start()
                stdout, stderr = proc.get_stdout(), proc.get_stderr()

            assert len(stderr) == 0, f"Stderr is not empty: {stderr}"
            await self.config.assert_match_daemon_start(stdout)
            yield self
        finally:
            try:
                await self.quit()
            except ProcessExecError as exc:
                if "Error: DaemonIsNotRunning" not in exc.stderr:
                    log.error(exc)
                    await self.kill()
                    await self.remove_socket()
                else:
                    log.info("Tried to quit but daemon is already not running")
            finally:
                await self.remove_identity_file()

    async def is_alive(self) -> bool:
        try:
            stdout, _ = await self.execute_command(Command.is_alive())
            return "Command executed successfully" in stdout
        except ProcessExecError as exc:
            if "Obtaining identity, ignoring" in exc.stdout:
                raise TeliodObtainingIdentity() from exc
            if "Error: DaemonIsNotRunning" in exc.stderr:
                return False
            if "Connection reset by peer" in exc.stderr:
                return False
            raise exc

    async def get_status(self) -> str:
        status, _ = await self.execute_command(Command.get_status())
        return status

    async def quit(self) -> None:
        stdout, stderr = await self.execute_command(Command.quit_daemon())
        assert (
            "Command executed successfully" in stdout
        ), f"Failed to execute quit-daemon command: {stderr}"

        assert (
            not await self.is_alive()
        ), "Quit command was sent successfully but daemon's still running"
        assert (
            not await self.socket_exists()
        ), "Daemon's not running but socket still exists"

    async def kill(self) -> None:
        try:
            await self.connection.create_process(
                ["killall", "-w", "-s", "SIGTERM", "teliod"]
            ).execute()
            assert (
                not await self.is_alive()
            ), "SIGTERM was sent but daemon's still running"
        except ProcessExecError as exc:
            if "teliod: no process found" not in exc.stderr:
                raise

    async def remove_logs(self) -> None:
        for path in [self.config.paths.daemon_log, self.config.paths.lib_log]:
            await self.connection.create_process(["rm", "-f", str(path)]).execute()
            await self.connection.create_process(
                ["test", "!", "-f", str(path)]
            ).execute()

    async def socket_exists(self) -> bool:
        try:
            await self.connection.create_process(
                ["test", "-e", str(self.config.paths.socket_file)]
            ).execute()
            return True
        except ProcessExecError as exc:
            assert (exc.returncode, exc.stdout, exc.stderr) == (1, "", "")
            return False

    async def remove_socket(self):
        await self.connection.create_process(
            ["rm", "-f", str(self.config.paths.socket_file)]
        ).execute()

    async def wait_for_teliod_socket(self):
        start_time = time.monotonic()
        while time.monotonic() - start_time < self.START_TIMEOUT_S:
            try:
                if await asyncio.wait_for(
                    self.socket_exists(), self.SOCKET_CHECK_INTERVAL_S
                ):
                    return
            except TimeoutError:
                pass
            await asyncio.sleep(self.SOCKET_CHECK_INTERVAL_S)
        raise TimeoutError("teliod did not start within timeout")

    async def wait_for_vpn_connected_state(self):
        while True:
            status = json.loads(await self.get_status())
            for ext_node in status["external_nodes"]:
                if ext_node["is_vpn"] and ext_node["state"] == "connected":
                    return
            await asyncio.sleep(self.TELIOD_CMD_CHECK_INTERVAL_S)

    async def wait_for_meshnet_ip_on_meshmap(self) -> Any:
        while True:
            status = json.loads(await self.get_status())
            if status["meshnet_ip"]:
                return status
            await asyncio.sleep(self.TELIOD_CMD_CHECK_INTERVAL_S)

    @asynccontextmanager
    async def setup_interface(
        self, ip_addresses: List[str], vpn_routes: bool
    ) -> AsyncIterator:
        """
        Setups interface addresses and routes manually.

        This function should only be used when interface config provider
        is set to 'manual' on the teliod config.
        This is not checked by this function. (TODO: LLT-6476)
        """
        router = LinuxRouter(self.connection, IPStack.IPv4)
        try:
            router.set_interface_name("teliod")
            await router.setup_interface(ip_addresses)
            await router.create_meshnet_route()
            if vpn_routes:
                await router.create_vpn_route()
            yield
        finally:
            if vpn_routes:
                await router.delete_vpn_route()
            await router.delete_exit_node_route()
            await router.delete_interface()

    @staticmethod
    def generate_new_device_keys() -> Dict[str, str]:
        (private_key, public_key) = Key.key_pair()
        hw_identifier = uuid.uuid4()
        return {
            "private_key": str(private_key),
            "public_key": str(public_key),
            "hardware_identifier": str(hw_identifier),
        }

    async def register_device_on_core(
        self, device_keys: Optional[Dict[str, str]] = None, dump_to_file=True
    ) -> tuple[Node, Dict[str, str]]:
        if device_keys is None:
            device_keys = Teliod.generate_new_device_keys()

        payload = {
            "public_key": device_keys["public_key"],
            "hardware_identifier": device_keys["hardware_identifier"],
            "os": "linux",
            "os_version": "teliod",
        }
        core_response = await send_https_request(
            self.connection,
            f"{CORE_API_URL}/v1/meshnet/machines",
            "POST",
            CORE_API_CA_CERTIFICATE_PATH,
            data=str(payload).replace("'", '"'),
            authorization_header=CORE_API_BEARER_AUTHORIZATION_HEADER,
        )
        assert core_response

        device_id = {
            "hw_identifier": device_keys["hardware_identifier"],
            "private_key": list(base64.b64decode(device_keys["private_key"])),
            "machine_identifier": core_response["identifier"],
        }

        device_id_json = json.dumps(device_id)
        log.debug("Device ID: %s", device_id_json)

        if dump_to_file:
            await self.write_identity_file(device_id_json)

        node: Node = self._api.register(
            "teliod",
            "teliod",
            device_keys["private_key"],
            device_keys["public_key"],
            True,
            IPStack.IPv4,
            core_response["ip_addresses"],
        )
        self._api.prepare_all_vpn_servers()

        return (node, device_id)

    @asynccontextmanager
    async def setup_vpn_public_key(self, key: str) -> AsyncIterator:
        """
        Because VPN server keys are generated only at runtime, this generator
        function inserts them to the config file, reverting
        back to 'public-key-placeholder' on _aexit_.
        """
        try:
            await self.connection.create_process([
                "sed",
                "-i",
                f's#"server_pubkey": .*#"server_pubkey": "{key}"#g',
                str(self.config.path()),
            ]).execute()
            yield
        finally:
            await self.connection.create_process([
                "sed",
                "-i",
                's#"server_pubkey": .*#"server_pubkey": "public-key-placeholder"#g',
                str(self.config.path()),
            ]).execute()

    async def remove_identity_file(self):
        try:
            await self.connection.create_process([
                "rm",
                str(self.config.paths.device_identity_path()),
            ]).execute()
        except ProcessExecError as exc:
            if "No such file or directory" in exc.stderr:
                pass

    async def read_identity_file(self) -> Dict[str, Any]:
        proc = await self.connection.create_process([
            "cat",
            str(self.config.paths.device_identity_path()),
        ]).execute()
        device_id = json.loads(proc.get_stdout())
        log.debug("Device identity file read: %s", device_id)

        return device_id

    async def write_identity_file(self, dev_identity_json: str) -> None:
        # TODO: [LLT-6476] check if configurations need to provide a custom id file path.
        # Otherwise just dump device_id_json directly on the default device identity path.
        if self.config.config_type in [
            IfcConfigType.VPN_IPROUTE,
            IfcConfigType.VPN_MANUAL,
        ]:
            await self.connection.create_process(
                ["mkdir", "-p", "/etc/teliod"]
            ).execute()
            await self.connection.create_process(
                ["sh", "-c", f"echo '{dev_identity_json}' > /etc/teliod/data.json"]
            ).execute()
        else:
            await self.connection.create_process(
                ["mkdir", "-p", str(self.config.paths.teliod_local_data_dir)]
            ).execute()
            await self.connection.create_process([
                "sh",
                "-c",
                f"echo '{dev_identity_json}' > {self.config.paths.device_identity_path()}",
            ]).execute()

    async def whitelist_device_on_the_vpn_servers(
        self, device_identity: Dict[str, Any], ipv4_addresses: List[str]
    ):
        """
        We reregister the device on the local API just with the sole goal of whitelisting it
        on the vpn servers.
        """
        try:
            self._api.remove("teliod")
        except:
            pass
        private_key = base64.b64encode(bytes(device_identity["private_key"])).decode()
        public_key = generate_public_key(private_key)
        _ = self._api.register(
            "teliod",
            "teliod",
            private_key,
            public_key,
            ip_addresses=ipv4_addresses,
        )
        self._api.prepare_all_vpn_servers()
