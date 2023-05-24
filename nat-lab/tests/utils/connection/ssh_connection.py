from utils.connection import Connection, TargetOS
from utils.process import Process, SshProcess
from typing import List
import asyncssh
from utils import cmd_exe_escape
import shlex


class SshConnection(Connection):
    _connection: asyncssh.SSHClientConnection

    def __init__(self, connection: asyncssh.SSHClientConnection):
        self._connection = connection

    def create_process(
        self,
        command: List[str],
    ) -> "Process":
        if self._target_os == TargetOS.Windows:
            escape_argument = cmd_exe_escape.escape_argument
        elif self._target_os == TargetOS.Linux or self._target_os == TargetOS.Mac:
            escape_argument = shlex.quote
        else:
            assert False, f"not supported target_os '{self._target_os}'"

        return SshProcess(self._connection, command, escape_argument)
