import asyncssh
import shlex
import subprocess
import utils.vm.mac_vm_util as utils_mac
import utils.vm.windows_vm_util as utils_win
from .connection import Connection, TargetOS, ConnectionTag, setup_ephemeral_ports
from contextlib import asynccontextmanager
from logging import INFO, DEBUG
from typing import List, AsyncIterator
from utils import cmd_exe_escape
from utils.logger import log
from utils.process import Process, SshProcess


class SshConnection(Connection):
    _connection: asyncssh.SSHClientConnection

    def __init__(
        self,
        connection: asyncssh.SSHClientConnection,
        tag: ConnectionTag,
    ):
        if tag in [ConnectionTag.VM_WINDOWS_1, ConnectionTag.VM_WINDOWS_2]:
            target_os = TargetOS.Windows
        elif tag is ConnectionTag.VM_MAC:
            target_os = TargetOS.Mac
        else:
            assert False, format(
                "Can't create ssh connection for the provided tag: %s", tag.name
            )

        super().__init__(target_os, tag)
        self._connection = connection

    async def __aenter__(self):
        await setup_ephemeral_ports(self)
        return self

    async def __aexit__(self, *_):
        pass

    @classmethod
    @asynccontextmanager
    async def new_connection(
        cls,
        ip: str,
        tag: ConnectionTag,
        copy_binaries: bool = False,
    ) -> AsyncIterator["SshConnection"]:
        subprocess.check_call(
            ["sudo", "bash", "vm_nat.sh", "disable"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        subprocess.check_call(
            ["sudo", "bash", "vm_nat.sh", "enable"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

        async with asyncssh.connect(
            ip,
            username="root" if tag is ConnectionTag.VM_MAC else "vagrant",
            password="vagrant",
            known_hosts=None,
        ) as ssh_connection:
            async with cls(ssh_connection, tag) as connection:
                if copy_binaries:
                    await connection.copy_binaries()

                if connection.target_os is TargetOS.Windows:
                    keys = await utils_win.get_network_interface_tunnel_keys(connection)
                    for key in keys:
                        await connection.create_process(
                            ["reg", "delete", key, "/F"],
                            quiet=True,
                        ).execute()

                yield connection

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
