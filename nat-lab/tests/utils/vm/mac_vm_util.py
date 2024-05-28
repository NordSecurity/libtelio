import asyncssh
import config
import subprocess
from config import get_root_path
from contextlib import asynccontextmanager
from typing import AsyncIterator
from utils.connection import Connection, SshConnection, TargetOS
from utils.process import ProcessExecError

VM_TCLI_DIR = config.LIBTELIO_BINARY_PATH_MAC_VM
VM_UNIFFI_DIR = config.UNIFFI_PATH_MAC_VM
FILES_COPIED = False


@asynccontextmanager
async def new_connection(ip: str = config.MAC_VM_IP) -> AsyncIterator[Connection]:
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
        ip,
        username="root",
        password="vagrant",  # NOTE: this is hardcoded password for transient vm existing only during the tests
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

    for directory in [VM_TCLI_DIR, VM_UNIFFI_DIR]:
        try:
            await connection.create_process(["rm", "-rf", directory]).execute()
        except ProcessExecError as exception:
            if exception.stderr.find("The system cannot find the file specified.") < 0:
                raise exception
        await connection.create_process(["mkdir", "-p", directory]).execute()

    DIST_PATH = "dist/darwin/macos/release/x86_64/"
    LOCAL_UNIFFI_PATH = "nat-lab/tests/uniffi/"

    files_to_copy = [
        (f"{DIST_PATH}tcli", f"{VM_TCLI_DIR}tcli", True),
        (
            f"{DIST_PATH}libtelio.dylib",
            f"{VM_UNIFFI_DIR}libtelio.dylib",
            True,
        ),
        (
            f"{LOCAL_UNIFFI_PATH}telio_bindings.py",
            f"{VM_UNIFFI_DIR}telio_bindings.py",
            True,
        ),
        (
            f"{LOCAL_UNIFFI_PATH}libtelio_remote.py",
            f"{VM_UNIFFI_DIR}libtelio_remote.py",
            True,
        ),
    ]
    for src, dst, set_exec in files_to_copy:
        await asyncssh.scp(
            get_root_path(src),
            (ssh_connection, dst),
        )
        if set_exec:
            await connection.create_process(["chmod", "+x", dst]).execute()

    FILES_COPIED = True
