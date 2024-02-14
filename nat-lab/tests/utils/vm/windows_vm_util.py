import asyncssh
import subprocess
from config import (
    get_root_path,
    LIBTELIO_BINARY_PATH_WINDOWS_VM,
    UNIFFI_PATH_WINDOWS_VM,
    WINDOWS_1_VM_IP,
)
from contextlib import asynccontextmanager
from typing import AsyncIterator
from utils.connection import Connection, SshConnection, TargetOS
from utils.process import ProcessExecError

VM_TCLI_DIR = LIBTELIO_BINARY_PATH_WINDOWS_VM
VM_UNIFFI_DIR = UNIFFI_PATH_WINDOWS_VM
VM_SYSTEM32 = "C:\\Windows\\System32"
FILES_COPIED = False


@asynccontextmanager
async def new_connection(ip: str = WINDOWS_1_VM_IP) -> AsyncIterator[Connection]:
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
        username="vagrant",
        password="vagrant",  # NOTE: this is hardcoded password for transient vm existing only during the tests
        known_hosts=None,
        options=ssh_options,
    ) as ssh_connection:
        connection = SshConnection(ssh_connection, TargetOS.Windows)

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
            await connection.create_process(["rmdir", "/s", "/q", directory]).execute()
        except ProcessExecError as exception:
            if (
                exception.stderr.find("The system cannot find the file specified") < 0
                and exception.stderr.find("The system cannot find the path specified")
                < 0
            ):
                raise exception
        try:
            await connection.create_process(["mkdir", directory]).execute()
        except ProcessExecError as exception:
            if (
                exception.stderr.find(
                    f"A subdirectory or file {directory} already exists."
                )
                < 0
            ):
                raise exception

    DIST_DIR = "dist/windows/release/x86_64/"
    LOCAL_UNIFFI_DIR = "nat-lab/tests/uniffi/"

    files_to_copy = [
        (f"{DIST_DIR}*", VM_TCLI_DIR, False),
        (f"{LOCAL_UNIFFI_DIR}telio_bindings.py", VM_UNIFFI_DIR, False),
        (f"{LOCAL_UNIFFI_DIR}libtelio_remote.py", VM_UNIFFI_DIR, False),
        (f"{DIST_DIR}telio.dll", f"{VM_UNIFFI_DIR}", False),
        (f"{DIST_DIR}sqlite3.dll", VM_UNIFFI_DIR, True),
        (f"{DIST_DIR}wireguard.dll", VM_UNIFFI_DIR, False),
        (f"{DIST_DIR}wintun.dll", VM_SYSTEM32, False),
    ]
    for src, dst, allow_missing in files_to_copy:
        try:
            await asyncssh.scp(
                get_root_path(src),
                (ssh_connection, dst),
            )
        except FileNotFoundError as exception:
            if not allow_missing or str(exception).find(src) < 0:
                raise exception

    FILES_COPIED = True
