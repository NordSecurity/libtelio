import asyncssh
import shlex
import tests.utils.connection_util  # pylint: disable=cyclic-import
import tests.utils.vm.mac_vm_util as utils_mac
import tests.utils.vm.openwrt_vm_util as utils_openwrt
import tests.utils.vm.windows_vm_util as utils_win
from .connection import Connection, TargetOS, ConnectionTag, setup_ephemeral_ports
from contextlib import asynccontextmanager
from logging import INFO, DEBUG
from tests.utils import cmd_exe_escape
from tests.utils.connection.docker_connection import DOCKER_VM_MAP
from tests.utils.logger import log
from tests.utils.process import Process, SshProcess
from typing import List, AsyncIterator
from uuid import uuid4


class SshConnection(Connection):
    _connection: asyncssh.SSHClientConnection
    _connection_id: str

    def __init__(
        self,
        connection: asyncssh.SSHClientConnection,
        tag: ConnectionTag,
    ):
        if tag in [ConnectionTag.VM_WINDOWS_1, ConnectionTag.VM_WINDOWS_2]:
            target_os = TargetOS.Windows
        elif tag is ConnectionTag.VM_MAC:
            target_os = TargetOS.Mac
        elif tag in [
            ConnectionTag.VM_OPENWRT_GW_1,
            ConnectionTag.VM_LINUX_NLX_1,
            ConnectionTag.VM_LINUX_FULLCONE_GW_1,
            ConnectionTag.VM_LINUX_FULLCONE_GW_2,
        ]:
            target_os = TargetOS.Linux
        else:
            assert False, format(
                "Can't create ssh connection for the provided tag: %s", tag.name
            )

        super().__init__(target_os, tag)
        self._connection = connection
        self._connection_id = str(uuid4())

    async def __aenter__(self):
        log.info(
            "[%s] SSH connection opened (conn_id=%s)",
            self.tag.name,
            self._connection_id,
        )
        await setup_ephemeral_ports(self)
        return self

    async def __aexit__(self, *_):
        log.info(
            "[%s] SSH connection closed (conn_id=%s)",
            self.tag.name,
            self._connection_id,
        )

    @classmethod
    @asynccontextmanager
    async def new_connection(
        cls,
        ip: str,
        tag: ConnectionTag,
        copy_binaries: bool = False,
    ) -> AsyncIterator["SshConnection"]:
        username = "root"
        password: str | None = "root"
        if tag is ConnectionTag.VM_MAC:
            username = "root"
            password = "jobs"
        elif tag in [ConnectionTag.VM_WINDOWS_1, ConnectionTag.VM_WINDOWS_2]:
            username = "bill"
            password = "gates"
        elif tag is ConnectionTag.VM_OPENWRT_GW_1:
            password = None

        try:
            async with asyncssh.connect(
                ip,
                username=username,
                password=password,
                known_hosts=None,
                agent_path=None,
            ) as ssh_connection:
                async with cls(ssh_connection, tag) as connection:
                    if copy_binaries:
                        await connection.copy_binaries()

                    if connection.target_os is TargetOS.Windows:
                        keys = await utils_win.get_network_interface_tunnel_keys(
                            connection
                        )
                        for key in keys:
                            await connection.create_process(
                                ["reg", "delete", key, "/F"],
                                quiet=True,
                            ).execute()

                    yield connection
        except OSError:
            if tag in [ConnectionTag.VM_WINDOWS_1, ConnectionTag.VM_WINDOWS_2]:
                try:
                    async with tests.utils.connection_util.new_connection_raw(
                        DOCKER_VM_MAP[tag]
                    ) as conn:
                        async with conn.create_process(
                            ["nc", "-q", "5", "-w", "5", "localhost", "7100"]
                        ).run() as nc:
                            await nc.wait_stdin_ready()
                            await nc.write_stdin("info status\n")
                            await nc.is_done()
                            log.error("Windows VM status: %s", tag)
                            log.error(nc.get_stdout())
                            log.error(nc.get_stderr())

                        async def print_event_log(log_name: str):
                            qga = await conn.create_process([
                                "python3",
                                "/run/qga.py",
                                "powershell",
                                "-Command",
                                f"Get-EventLog -LogName {log_name} -Newest 40 | format-table -wrap",
                            ]).execute()
                            log.error("Windows VM {%s} Event Log: {%s}:", log_name, tag)
                            log.error(qga.get_stdout())
                            log.error(qga.get_stderr())

                        await print_event_log("Application")
                        await print_event_log("System")
                        await print_event_log("Security")

                except Exception as e:  # pylint: disable=broad-exception-caught
                    log.error("An error occurred when querying Windows VM status")
                    log.error(e)
            raise

    def create_process(
        self, command: List[str], kill_id=None, term_type=None, quiet=False
    ) -> "Process":

        if not quiet:
            log_level = INFO
        else:
            log_level = DEBUG
        log.log(log_level, "[%s] Executing %s", self.tag.name, " ".join(command))

        if self.target_os == TargetOS.Windows:
            escape_argument = cmd_exe_escape.escape_argument
        elif self.target_os in [TargetOS.Linux, TargetOS.Mac]:
            escape_argument = shlex.quote
        else:
            assert False, f"not supported target_os '{self.target_os}'"

        return SshProcess(
            self._connection, self.tag.name, command, escape_argument, term_type
        )

    async def get_ip_address(self) -> tuple[str, str]:
        ip = self._connection._host  # pylint: disable=protected-access
        return (ip, ip)

    async def download(self, remote_path: str, local_path: str) -> None:
        """Copy file from 'remote_path' on the node connected via this connection, to local directory 'local_path'"""
        try:
            await asyncssh.scp(
                (self._connection, remote_path), local_path, recurse=True
            )
        except asyncssh.SFTPFailure as e:
            if "No such file or directory" in e.reason:
                return
            raise e

    async def copy_binaries(self) -> None:
        if self.target_os is TargetOS.Windows:
            await utils_win.copy_binaries(self._connection, self)
        elif self.target_os is TargetOS.Mac:
            await utils_mac.copy_binaries(self._connection, self)
        elif (
            self.target_os is TargetOS.Linux  # type: ignore[redundant-expr]
            and self.tag is ConnectionTag.VM_OPENWRT_GW_1
        ):
            await utils_openwrt.copy_binaries(self._connection, self)

    async def upload_file(self, local_file_path: str, remote_file_path: str) -> None:
        """Upload file from 'local_file_path' to 'remote_file_path' on the connected node"""
        try:
            await asyncssh.scp(
                local_file_path, (self._connection, remote_file_path), recurse=True
            )
        except asyncssh.SFTPFailure as e:
            if "No such file or directory" in e.reason:
                return
            raise e
