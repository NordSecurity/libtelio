import asyncssh
import shlex
from .connection import Connection, TargetOS
from datetime import datetime
from typing import List
from utils import cmd_exe_escape
from utils.process import Process, SshProcess


class SshConnection(Connection):
    _connection: asyncssh.SSHClientConnection
    _target_os: TargetOS

    def __init__(self, connection: asyncssh.SSHClientConnection, target_os: TargetOS):
        super().__init__(target_os)
        self._connection = connection
        self._target_os = target_os

    def create_process(self, command: List[str]) -> "Process":
        print(datetime.now(), "Executing", command, "on", self.target_os)
        if self._target_os == TargetOS.Windows:
            escape_argument = cmd_exe_escape.escape_argument
        elif self._target_os in [TargetOS.Linux, TargetOS.Mac]:
            escape_argument = shlex.quote
        else:
            assert False, f"not supported target_os '{self._target_os}'"

        request_pty: bool | str
        if self._target_os == TargetOS.Mac:
            request_pty = "force"
        else:
            request_pty = True

        return SshProcess(self._connection, command, escape_argument, request_pty)

    async def get_ip_address(self) -> tuple[str, str]:
        ip = self._connection._host  # pylint: disable=protected-access
        return (ip, ip)

    def target_name(self) -> str:
        return str(self._target_os)
