import asyncssh
import os
from config import get_root_path, LIBTELIO_BINARY_PATH_VM_MAC, UNIFFI_PATH_VM_MAC
from utils.connection import Connection
from utils.process import ProcessExecError

VM_TCLI_DIR = LIBTELIO_BINARY_PATH_VM_MAC
VM_UNIFFI_DIR = UNIFFI_PATH_VM_MAC


async def copy_binaries(
    ssh_connection: asyncssh.SSHClientConnection, connection: Connection
) -> None:
    for directory in [VM_TCLI_DIR, VM_UNIFFI_DIR]:
        try:
            await connection.create_process(
                ["rm", "-rf", directory], quiet=True
            ).execute()
        except ProcessExecError as exception:
            if exception.stderr.find("The system cannot find the file specified.") < 0:
                raise exception
        await connection.create_process(
            ["mkdir", "-p", directory], quiet=True
        ).execute()

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
            await connection.create_process(["chmod", "+x", dst], quiet=True).execute()

    await asyncssh.scp(
        get_root_path("nat-lab/bin/mac/list_interfaces_with_router_property.py"),
        (ssh_connection, f"{VM_TCLI_DIR}"),
    )
