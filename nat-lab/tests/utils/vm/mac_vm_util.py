import asyncssh
import config
import subprocess
from config import get_root_path
from contextlib import asynccontextmanager
from typing import AsyncIterator
from utils.connection import Connection, SshConnection, TargetOS
from utils.process import ProcessExecError

VM_TCLI_DIR = config.LIBTELIO_BINARY_PATH_VM
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
        config.MAC_VM_IP,
        username="root",
        password="vagrant",
        known_hosts=None,
        options=ssh_options,
    ) as ssh_connection:
        connection = SshConnection(ssh_connection, TargetOS.Mac)

        await _copy_binaries(ssh_connection, connection)

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
        await connection.create_process(["rm", "-rf", VM_TCLI_DIR]).execute()
    except ProcessExecError as exception:
        if exception.stderr.find("The system cannot find the file specified.") < 0:
            raise exception

    await connection.create_process(["mkdir", "-p", VM_TCLI_DIR]).execute()
    await asyncssh.scp(
        get_root_path("dist/darwin/macos/release/x86_64/tcli"),
        (ssh_connection, f"{VM_TCLI_DIR}"),
    )
    await connection.create_process(["chmod", "+x", f"{VM_TCLI_DIR}/tcli"]).execute()
    FILES_COPIED = True
