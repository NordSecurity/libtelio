import asyncssh
import shlex
import subprocess
import utils.vm.mac_vm_util as utils_mac
import utils.vm.windows_vm_util as utils_win
from .connection import Connection, TargetOS, ConnectionTag, setup_ephemeral_ports
from contextlib import asynccontextmanager
from datetime import datetime
from typing import List, AsyncIterator
from utils import cmd_exe_escape
from utils.process import Process, SshProcess


class SshConnection(Connection):
    _connection: asyncssh.SSHClientConnection

    def __init__(
        self,
        connection: asyncssh.SSHClientConnection,
        tag: ConnectionTag,
    ):
        if tag in [ConnectionTag.WINDOWS_VM_1, ConnectionTag.WINDOWS_VM_2]:
            target_os = TargetOS.Windows
        elif tag is ConnectionTag.MAC_VM:
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

    async def __aexit__(self, exc_type, exc, tb):
        return None

    @classmethod
    @asynccontextmanager
    async def new_connection(
        cls,
        ip: str,
        tag: ConnectionTag,
        copy_binaries: bool = False,
        reenable_nat=False,
    ) -> AsyncIterator["SshConnection"]:
        if reenable_nat:
            subprocess.check_call(["sudo", "bash", "vm_nat.sh", "disable"])
            subprocess.check_call(["sudo", "bash", "vm_nat.sh", "enable"])

        ssh_options = asyncssh.SSHClientConnectionOptions(
            encryption_algs=[
                "aes128-gcm@openssh.com",
                "aes256-ctr",
                "aes192-ctr",
                "aes128-ctr",
            ],
            compression_algs=None,
        )

        async with asyncssh.connect(
            ip,
            username="root" if tag is ConnectionTag.MAC_VM else "vagrant",
            password="vagrant",  # Hardcoded password for transient VM used in tests
            known_hosts=None,
            options=ssh_options,
        ) as ssh_connection:
            async with cls(ssh_connection, tag) as connection:
                if copy_binaries:
                    await connection.copy_binaries()

                if connection.target_os is TargetOS.Windows:
                    keys = await utils_win.get_network_interface_tunnel_keys(connection)
                    for key in keys:
                        await connection.create_process(
                            ["reg", "delete", key, "/F"]
                        ).execute()

                yield connection

    def create_process(
        self, command: List[str], kill_id=None, term_type=None
    ) -> "Process":
        print(datetime.now(), "Executing", command, "on", self.target_os)
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
