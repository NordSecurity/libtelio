import asyncio
import json
import os
import re
import time
from config import LIBTELIO_BINARY_PATH_DOCKER
from contextlib import AsyncExitStack, asynccontextmanager
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import AsyncIterator
from utils.connection import Connection
from utils.logger import log
from utils.process import Process, ProcessExecError


class TeliodObtainingIdentity(Exception):
    pass


class IfcConfigType(Enum):
    DEFAULT = "config.json"
    VPN_MANUAL = "config_with_vpn_manual_setup.json"
    VPN_IPROUTE = "config_with_vpn_iproute_setup.json"


@dataclass(frozen=True)
class Paths:
    exec_path: Path = Path(f"{LIBTELIO_BINARY_PATH_DOCKER}/teliod")
    config_dir: Path = Path("/etc/teliod")
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

    def config_path(self, config_type: IfcConfigType = IfcConfigType.DEFAULT) -> Path:
        return self.config_dir / config_type.value


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
    ) -> None:
        self._connection: Connection = connection
        self._exit_stack: AsyncExitStack = exit_stack
        self.config: Config = config

    async def execute_command(
        self,
        cmd: Command,
    ) -> tuple[str, str]:
        try:
            proc = await self._connection.create_process(cmd).execute()
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
            self._connection.create_process(cmd).run()
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

    async def is_alive(self) -> bool:
        try:
            stdout, _ = await self.execute_command(Command.is_alive())
            return "Command executed successfully" in stdout
        except ProcessExecError as exc:
            if "Obtaining identity, ignoring" in exc.stdout:
                raise TeliodObtainingIdentity() from exc
            if "Error: DaemonIsNotRunning" in exc.stderr:
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
            await self._connection.create_process(
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
            await self._connection.create_process(["rm", "-f", str(path)]).execute()
            await self._connection.create_process(
                ["test", "!", "-f", str(path)]
            ).execute()

    async def socket_exists(self) -> bool:
        try:
            await self._connection.create_process(
                ["test", "-e", str(self.config.paths.socket_file)]
            ).execute()
            return True
        except ProcessExecError as exc:
            assert (exc.returncode, exc.stdout, exc.stderr) == (1, "", "")
            return False

    async def remove_socket(self):
        await self._connection.create_process(
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
            await asyncio.sleep(0.5)
        raise TimeoutError("teliod did not start within timeout")

    async def wait_for_vpn_connected_state(self):
        while True:
            status = json.loads(await self.get_status())
            for ext_node in status["external_nodes"]:
                if ext_node["is_vpn"] and ext_node["state"] == "connected":
                    return
            await asyncio.sleep(self.TELIOD_CMD_CHECK_INTERVAL_S)
