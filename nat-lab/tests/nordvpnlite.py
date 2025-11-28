import asyncio
import json
import os
import re
import time
from contextlib import AsyncExitStack, asynccontextmanager
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from tests.config import (
    CORE_API_CREDENTIALS,
    LIBTELIO_BINARY_PATH_DOCKER,
    LIBTELIO_LOCAL_IP,
    CORE_API_URL,
    CORE_API_CA_CERTIFICATE_PATH,
    WG_SERVER,
    WG_SERVERS,
)
from tests.helpers import send_https_request, setup_connections
from tests.mesh_api import API, Node
from tests.test_core_api import register_vpn_server_key
from tests.uniffi.telio_bindings import generate_public_key
from tests.utils.connection import Connection, ConnectionTag
from tests.utils.logger import log
from tests.utils.process import Process, ProcessExecError
from tests.utils.router import IPStack
from tests.utils.router.linux_router import LinuxRouter
from tests.utils.testing import get_current_test_log_path
from typing import AsyncIterator, Optional


class IgnoreableError(Exception):
    pass


class IfcConfigType(Enum):
    DEFAULT = "config.json"
    MANUAL = "config_with_manual_setup.json"
    IPROUTE = "config_with_iproute_setup.json"
    VPN_COUNTRY_PL = "config_with_vpn_country_pl.json"
    VPN_COUNTRY_DE = "config_with_vpn_country_de.json"
    VPN_COUNTRY_EMPTY = "config_with_vpn_country_empty.json"
    VPN_OPENWRT_UCI_PL = "config_openwrt_uci_pl_setup.json"
    VPN_OPENWRT_UCI_DE = "config_openwrt_uci_de_setup.json"

    @classmethod
    def _missing_(cls, value):
        return cls.MANUAL


@dataclass(frozen=True)
class Paths:
    exec_path: Path = Path(f"{LIBTELIO_BINARY_PATH_DOCKER}/nordvpnlite")
    config_dir: Path = Path("/etc/nordvpnlite")
    log_dir: Path = Path("/var/log")
    run_dir: Path = Path("/run")

    def __post_init__(self):
        if os.environ.get("PYTEST_CURRENT_TEST") and self.exec_path.parent != Path("."):
            if not self.exec_path.exists():
                raise FileNotFoundError(
                    f"NordVPN Lite executable not found: {self.exec_path}"
                )

    @property
    def socket_file(self) -> Path:
        return self.run_dir / "nordvpnlited.sock"

    @property
    def daemon_log(self) -> Path:
        return self.log_dir / "nordvpnlite.log"

    @property
    def lib_log(self) -> Path:
        return self.log_dir / "nordvpnlite_natlab.log"

    def config_path(self, config_type: IfcConfigType) -> Path:
        return self.config_dir / config_type.value


class Config:
    def __init__(
        self,
        config_type: IfcConfigType = IfcConfigType(None),
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


class NordVpnLite:
    SOCKET_CHECK_INTERVAL_S = 0.5
    NORDVPNLITE_CMD_CHECK_INTERVAL_S = 10  # TODO (LLT-6693): revert back to 1

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
        self._node: Node = Node()

    @classmethod
    async def new(
        cls,
        exit_stack: AsyncExitStack,
        config_type: IfcConfigType = IfcConfigType(None),
        no_detach: bool = False,
        connection_tag: ConnectionTag = ConnectionTag.DOCKER_CONE_CLIENT_1,
        connection: Optional[Connection] = None,
        vpn_public_key: Optional[str] = str(WG_SERVER["public_key"]),
    ) -> "NordVpnLite":
        if not connection:
            connection = (await setup_connections(exit_stack, [connection_tag]))[
                0
            ].connection
        nordvpnlite = cls(connection, exit_stack, config=Config(config_type, no_detach))
        if vpn_public_key:
            await exit_stack.enter_async_context(
                nordvpnlite.setup_vpn_public_key(vpn_public_key)
            )

        return nordvpnlite

    async def execute_command(
        self,
        cmd: list,
    ) -> tuple[str, str]:
        # TODO(LLT-6785): remove the sleep
        await asyncio.sleep(5)

        start_time = time.time()
        try:
            cmd = [str(self.config.paths.exec_path)] + cmd
            proc = await self.connection.create_process(cmd).execute()
            stdout, stderr = proc.get_stdout(), proc.get_stderr()
            log.debug(
                "'%s' stdout: '%s', stderr: '%s'",
                " ".join(str(item) for item in cmd),
                stdout,
                stderr,
            )
            time_took = time.time() - start_time
            log.debug("Command: [%s] took %.3f seconds", cmd, time_took)
            return stdout, stderr
        except ProcessExecError as exc:
            time_took = time.time() - start_time
            log.debug("Command: [%s] took %.3f seconds", cmd, time_took)
            log.debug("Exception occured while executing nordvpnlite command: %s", exc)
            raise

    async def run_command(
        self,
        cmd: list,
    ) -> Process:
        cmd = [str(self.config.paths.exec_path)] + cmd
        proc = await self._exit_stack.enter_async_context(
            self.connection.create_process(cmd).run()
        )
        return proc

    @asynccontextmanager
    async def start(self, cleanup: bool = True) -> AsyncIterator["NordVpnLite"]:
        log.info("NordVPN Lite starting..")
        try:
            await self.remove_logs()

            async def wait_for_nordvpnlite_start():
                await self.wait_for_nordvpnlite_socket()
                while True:
                    try:
                        if not await self.is_alive():
                            raise RuntimeError(
                                "socket exists but daemon's not running."
                            )
                        break
                    except IgnoreableError:
                        await asyncio.sleep(self.NORDVPNLITE_CMD_CHECK_INTERVAL_S)
                        continue

            cmd = ["start"]
            if not self.config.no_detach:
                cmd.append("--config-file")
                cmd.append(str(self.config.path()))
                stdout, stderr = await self.execute_command(cmd)
                await wait_for_nordvpnlite_start()
            else:
                cmd.append("--no-detach")
                cmd.append("--config-file")
                cmd.append(str(self.config.path()))
                proc = await self.run_command(cmd)
                await wait_for_nordvpnlite_start()
                stdout, stderr = proc.get_stdout(), proc.get_stderr()

            assert len(stderr) == 0, f"Stderr is not empty: {stderr}"
            await self.config.assert_match_daemon_start(stdout)
            yield self
        finally:
            if cleanup:
                await self.clean_up()
            else:
                log.info("NordVPN Lite skipping cleanup")

    async def clean_up(self) -> None:
        log.info("NordVPN Lite cleanup: exiting and removing socket (if exists)")
        try:
            await self.quit()
        except ProcessExecError as exc:
            if "Error: DaemonIsNotRunning" not in exc.stderr:
                log.error(exc)
                await self.kill()
            else:
                log.info("Tried to quit but daemon is already not running")
            if await self.socket_exists():
                log.debug("Dangling socket found, removing it..")
                await self.remove_socket()
        finally:
            log.info("NordVPN Lite cleanup: saving logs")
            await self._save_logs()

    async def is_alive(self) -> bool:
        try:
            stdout, _ = await self.execute_command(["is-alive"])
            return "Command executed successfully" in stdout
        except ProcessExecError as exc:
            if "Error: DaemonIsNotRunning" in exc.stderr:
                return False
            raise exc

    async def get_status(self) -> str:
        try:
            status, _ = await self.execute_command(["status"])
            return status
        except ProcessExecError as exc:
            if "Daemon is not ready, ignoring" in exc.stdout:
                raise IgnoreableError() from exc
            # TODO: remove after LLT-6693
            if "ClientTimeoutError" in exc.stdout:
                raise IgnoreableError() from exc
            raise exc

    async def quit(self) -> None:
        stdout, stderr = await self.execute_command(["stop"])
        assert (
            "Command executed successfully" in stdout
            or "Daemon is already stopped" in stdout
        ), f"Failed to execute stop command: {stderr}"

        assert (
            not await self.is_alive()
        ), "Quit command was sent successfully but daemon's still running"
        assert (
            not await self.socket_exists()
        ), "Daemon's not running but socket still exists"

    async def kill(self) -> None:
        try:
            # OpenWrt doesn't support killall -w
            if self.config.paths.exec_path.parent == Path("."):
                await self.connection.create_process(
                    ["killall", "-s", "SIGTERM", "nordvpn"]
                ).execute()
            else:
                await self.connection.create_process(
                    ["killall", "-w", "-s", "SIGTERM", "nordvpnlite"]
                ).execute()
            assert (
                not await self.is_alive()
            ), "SIGTERM was sent but daemon's still running"
        except ProcessExecError as exc:
            if "nordvpnlite: no process found" not in exc.stderr:
                raise

    async def remove_config(self, path: Path) -> None:
        await self.connection.create_process(["rm", "-f", str(path)]).execute()
        await self.connection.create_process(["test", "!", "-f", str(path)]).execute()

    async def config_exists(self, path: Path) -> bool:
        try:
            await self.connection.create_process([
                "test",
                "-s",
                str(path),
            ]).execute()
            return True
        except ProcessExecError as exc:
            assert (exc.returncode, exc.stdout, exc.stderr) == (1, "", "")
            return False

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

    async def wait_for_nordvpnlite_socket(self):
        while True:
            try:
                if await asyncio.wait_for(
                    self.socket_exists(), self.SOCKET_CHECK_INTERVAL_S
                ):
                    return
            except TimeoutError:
                pass
            await asyncio.sleep(self.SOCKET_CHECK_INTERVAL_S)
        exc = TimeoutError("nordvpnlite did not start within timeout")
        log.error(exc)
        raise exc

    async def wait_for_vpn_connected_state(self):
        # TODO: remove after LLT-6693
        await asyncio.sleep(self.NORDVPNLITE_CMD_CHECK_INTERVAL_S)
        while True:
            try:
                status = json.loads(await self.get_status())
                if status["exit_node"]:
                    if status["exit_node"]["state"] == "connected":
                        return
                await asyncio.sleep(self.NORDVPNLITE_CMD_CHECK_INTERVAL_S)
            except IgnoreableError:
                await asyncio.sleep(self.NORDVPNLITE_CMD_CHECK_INTERVAL_S)
                continue

    async def wait_for_telio_running_status(self):
        # TODO: remove after LLT-6693
        await asyncio.sleep(self.NORDVPNLITE_CMD_CHECK_INTERVAL_S)
        while True:
            try:
                status = json.loads(await self.get_status())
                if status["telio_is_running"]:
                    return
                await asyncio.sleep(self.NORDVPNLITE_CMD_CHECK_INTERVAL_S)
            except IgnoreableError:
                await asyncio.sleep(self.NORDVPNLITE_CMD_CHECK_INTERVAL_S)
                continue

    @asynccontextmanager
    async def setup_interface(self, vpn_routes: bool) -> AsyncIterator:
        """
        Setups interface addresses and routes manually.

        This function should only be used when interface config provider
        is set to 'manual' on the nordvpnlite config.
        This is not checked by this function. (TODO: LLT-6476)
        """
        router = LinuxRouter(self.connection, IPStack.IPv4)
        try:
            router.set_interface_name("nordvpnlite")
            await router.setup_interface(self._node.ip_addresses)
            if vpn_routes:
                await router.create_vpn_route()
            yield
        finally:
            if vpn_routes:
                await router.delete_vpn_route()
            await router.delete_exit_node_route()
            await router.delete_interface()

    async def request_credentials_from_core(self) -> None:
        core_response = await send_https_request(
            self.connection,
            f"{CORE_API_URL}/v1/users/services/credentials",
            "GET",
            CORE_API_CA_CERTIFICATE_PATH,
            basic_auth=(
                CORE_API_CREDENTIALS["username"],
                CORE_API_CREDENTIALS["password"],
            ),
        )
        assert core_response

        node: Node = self._api.register(
            "nordvpnlite",
            "nordvpnlite",
            core_response["nordlynx_private_key"],
            generate_public_key(core_response["nordlynx_private_key"]),
            True,
            IPStack.IPv4,
            [LIBTELIO_LOCAL_IP],
        )
        self._node = node

        await self._api.prepare_all_vpn_servers()
        for country_id, server_config in enumerate(WG_SERVERS, start=1):
            await register_vpn_server_key(
                self.connection, str(server_config["public_key"]), country_id
            )

    @asynccontextmanager
    async def setup_vpn_public_key(self, pubkey: str) -> AsyncIterator:
        """
        Because VPN server keys are generated only at runtime, this generator
        function inserts them to the config file, reverting
        back to 'public-key-placeholder' on _aexit_.
        """
        config_path = f"data/nordvpnlite/{self.config.config_type.value}"
        with open(config_path, "r", encoding="UTF-8") as f:
            original_cfg = f.read()

        def update_public_key_in_json(content: str, new_key: str) -> str:
            try:
                config_data = json.loads(content)
                config_data["vpn"]["server"]["public_key"] = new_key
                return json.dumps(config_data, indent=2)
            except json.JSONDecodeError as e:
                raise RuntimeError(
                    f"Failed to parse config file as JSON: {config_path}\nError: {e}"
                ) from e

        try:
            updated_cfg = update_public_key_in_json(original_cfg, pubkey)
            with open(config_path, "w", encoding="UTF-8") as f:
                f.write(updated_cfg)

            yield
        finally:
            clean_cfg = update_public_key_in_json(
                original_cfg, "public-key-placeholder"
            )
            with open(config_path, "w", encoding="UTF-8") as f:
                f.write(clean_cfg)

    async def _save_logs(self) -> None:
        if os.environ.get("NATLAB_SAVE_LOGS") is None:
            return

        log_dir = get_current_test_log_path()
        os.makedirs(log_dir, exist_ok=True)

        log_files = [
            (self.config.paths.daemon_log, "nordvpnlite.log"),
            (self.config.paths.lib_log, "nordvpnlite_natlab.log"),
        ]

        for log_path, log_name in log_files:
            try:
                process = await self.connection.create_process(
                    ["cat", str(log_path)], quiet=True
                ).execute()
                log_content = process.get_stdout()

                filename = f"{self.connection.tag.name.lower()}_{log_name}"

                if len(filename.encode("utf-8")) > 256:
                    filename = f"{filename[:251]}.log"
                    i = 0
                    while os.path.exists(os.path.join(log_dir, filename)):
                        filename = f"{filename[:249]}_{i}.log"
                        i += 1

                with open(
                    os.path.join(log_dir, filename),
                    "w",
                    encoding="utf-8",
                ) as f:
                    f.write(log_content)

                log.info("Saved %s to %s", log_name, filename)

            except ProcessExecError as err:
                log.warning("Failed to save %s: %s", log_name, err)
