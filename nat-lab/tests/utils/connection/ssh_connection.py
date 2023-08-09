import asyncssh
import shlex
from .connection import Connection, TargetOS
from typing import List
from utils import cmd_exe_escape
from utils.process import Process, SshProcess


class SshConnection(Connection):
    _connection: asyncssh.SSHClientConnection

    def __init__(self, connection: asyncssh.SSHClientConnection, target_os: TargetOS):
        super().__init__(target_os)
        self._connection = connection

    def create_process(self, command: List[str]) -> "Process":
        if self._target_os == TargetOS.Windows:
            escape_argument = cmd_exe_escape.escape_argument
        elif self._target_os in [TargetOS.Linux, TargetOS.Mac]:
            escape_argument = shlex.quote
        else:
            assert False, f"not supported target_os '{self._target_os}'"

        return SshProcess(self._connection, command, escape_argument)
