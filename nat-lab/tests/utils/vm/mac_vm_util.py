import asyncssh
import os
import subprocess
from config import (
    get_root_path,
    LIBTELIO_BINARY_PATH_MAC_VM,
    MAC_VM_IP,
    UNIFFI_PATH_MAC_VM,
)
from contextlib import asynccontextmanager
from typing import AsyncIterator
from utils.connection import Connection, SshConnection, TargetOS
from utils.process import ProcessExecError

VM_TCLI_DIR = LIBTELIO_BINARY_PATH_MAC_VM
VM_UNIFFI_DIR = UNIFFI_PATH_MAC_VM


@asynccontextmanager
async def new_connection(
    ip: str = MAC_VM_IP, copy_binaries: bool = False
) -> AsyncIterator[Connection]:
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

        if copy_binaries:
            await _copy_binaries(ssh_connection, connection)

        try:
            yield connection
        finally:
            pass


async def _copy_binaries(
    ssh_connection: asyncssh.SSHClientConnection, connection: Connection
) -> None:
    for directory in [VM_TCLI_DIR, VM_UNIFFI_DIR]:
        try:
            await connection.create_process(["rm", "-rf", directory]).execute()
        except ProcessExecError as exception:
            if exception.stderr.find("The system cannot find the file specified.") < 0:
                raise exception
        await connection.create_process(["mkdir", "-p", directory]).execute()

    DIST_PATH = f"dist/darwin/macos/{os.getenv('TELIO_BIN_PROFILE')}/x86_64/"
    LOCAL_UNIFFI_PATH = "nat-lab/tests/uniffi/"
    LOCAL_BIN_DIR = "nat-lab/bin/"
    files_to_copy = [
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
        (f"{LOCAL_BIN_DIR}multicast.py", f"{VM_TCLI_DIR}multicast.py", True),
        (f"{LOCAL_BIN_DIR}netcat.py", f"{VM_TCLI_DIR}netcat.py", True),
        (
            f"{LOCAL_UNIFFI_PATH}serialization.py",
            f"{VM_UNIFFI_DIR}serialization.py",
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

    await asyncssh.scp(
        get_root_path("nat-lab/bin/mac/list_interfaces_with_router_property.py"),
        (ssh_connection, f"{VM_TCLI_DIR}"),
    )
