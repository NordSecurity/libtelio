import asyncssh
import config
import subprocess
from config import (
    get_root_path,
    LIBTELIO_BINARY_PATH_WINDOWS_VM,
    UNIFFI_PATH_WINDOWS_VM,
    PYTHON_PATH_WINDOWS_VM,
)
from contextlib import asynccontextmanager
from typing import AsyncIterator
from utils.connection import Connection, SshConnection, TargetOS
from utils.process import ProcessExecError

VM_TCLI_DIR = LIBTELIO_BINARY_PATH_WINDOWS_VM
VM_UNIFFI_DIR = UNIFFI_PATH_WINDOWS_VM
VM_PYTHON_DIR = PYTHON_PATH_WINDOWS_VM
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

    try:
        await connection.create_process(
            ["taskkill", "/IM", "python.exe", "/F"]
        ).execute()
    except:
        pass

    try:
        await connection.create_process(["mkdir", VM_UNIFFI_DIR]).execute()
    except:
        pass

    uniffi_files = [
        "libtelio.py",
        "libtelio_remote.py",
        "uniffi_libtelio.dll",
        "sqlite3.dll",
        "wintun.dll",
        "wireguard.dll",
    ]
    for file in uniffi_files:
        try:
            await connection.create_process(
                ["del", "/s", "/q", f"{VM_UNIFFI_DIR}\\{file}"]
            ).execute()
        except:
            pass
        try:
            await connection.create_process(
                ["del", "/s", "/q", f"{VM_PYTHON_DIR}\\{file}"]
            ).execute()
        except:
            pass
        await asyncssh.scp(
            get_root_path(f"libtelio/nat-lab/tests/uniffi/{file}"),
            (ssh_connection, VM_UNIFFI_DIR),
        )
        await asyncssh.scp(
            get_root_path(f"libtelio/nat-lab/tests/uniffi/{file}"),
            (ssh_connection, VM_PYTHON_DIR),
        )

    FILES_COPIED = True
