import asyncssh
import config
import subprocess
from config import get_root_path, LIBTELIO_BINARY_PATH_WINDOWS_VM
from contextlib import asynccontextmanager
from typing import AsyncIterator
from utils.connection import Connection, SshConnection, TargetOS
from utils.process import ProcessExecError

VM_TCLI_DIR = LIBTELIO_BINARY_PATH_WINDOWS_VM
FILES_COPIED = False


@asynccontextmanager
async def new_connection() -> AsyncIterator[Connection]:
    subprocess.check_call(["sudo", "bash", "vm_nat.sh", "disable"])
    subprocess.check_call(["sudo", "bash", "vm_nat.sh", "enable"])

    # Speedup large file transfer: https://github.com/ronf/asyncssh/issues/374
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
        config.WINDOWS_VM_IP,
        username="vagrant",
        password="vagrant",  # NOTE: this is hardcoded password for transient vm existing only during the tests
        known_hosts=None,
        options=ssh_options,
    ) as ssh_connection:
        connection = SshConnection(ssh_connection, TargetOS.Windows)

        await _copy_binaries(ssh_connection, connection)

        async def on_stdout(stdout: str) -> None:
            print(stdout)

        await connection.create_process(["route", "print"]).execute(
            stdout_callback=on_stdout,
            stderr_callback=on_stdout,
        )
        await connection.create_process(["ipconfig/all"]).execute(
            stdout_callback=on_stdout,
            stderr_callback=on_stdout,
        )

        try:
            yield connection
        finally:
            pass


async def _copy_binaries(
    ssh_connection: asyncssh.SSHClientConnection, connection: Connection
) -> None:
    global FILES_COPIED
    if FILES_COPIED:
        return

    try:
        await connection.create_process(["rmdir", "/s", "/q", VM_TCLI_DIR]).execute()
    except ProcessExecError as exception:
        if (
            exception.stderr.find("The system cannot find the file specified") < 0
            and exception.stderr.find("The system cannot find the path specified") < 0
        ):
            raise exception

    await connection.create_process(["mkdir", VM_TCLI_DIR]).execute()
    await asyncssh.scp(
        get_root_path("dist/windows/release/x86_64/*"), (ssh_connection, VM_TCLI_DIR)
    )
    FILES_COPIED = True
