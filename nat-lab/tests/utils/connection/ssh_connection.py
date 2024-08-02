import asyncssh
import os
import shlex
import tempfile
from .connection import Connection, TargetOS
from datetime import datetime
from typing import List
from utils import cmd_exe_escape
from utils.process import Process, SshProcess
from utils.testing import test_name_safe_for_file_name


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

        return SshProcess(self._connection, command, escape_argument)

    async def read_text_file(self, path) -> str:
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_file_name = os.path.join(temp_dir, "temp")
            await asyncssh.scp((self._connection, path), temp_file_name)
            with open(temp_file_name, "rb") as f:
                buf = f.read()
                try:
                    return buf.decode(encoding="utf-8", errors="strict")
                except UnicodeDecodeError as e:
                    log_dir = "logs"
                    os.makedirs(log_dir, exist_ok=True)
                    with open(
                        os.path.join(
                            log_dir, f"{test_name_safe_for_file_name()}_utf8error"
                        ),
                        "wb",
                    ) as backup:
                        backup.write(f"Exception occured: {e}\n\n".encode())
                        backup.write(buf)
                    return buf.decode(encoding="utf-8", errors="replace")

    async def get_ip_address(self) -> tuple[str, str]:
        ip = self._connection._host  # pylint: disable=protected-access
        return (ip, ip)

    def target_name(self) -> str:
        return str(self._target_os)
