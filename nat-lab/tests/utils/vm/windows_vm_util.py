import asyncssh
import subprocess
from config import (
    get_root_path,
    LIBTELIO_BINARY_PATH_WINDOWS_VM,
    UNIFFI_PATH_WINDOWS_VM,
    WINDOWS_1_VM_IP,
)
from contextlib import asynccontextmanager
from datetime import datetime
from typing import AsyncIterator, List
from utils.connection import Connection, SshConnection, TargetOS
from utils.process import ProcessExecError

VM_TCLI_DIR = LIBTELIO_BINARY_PATH_WINDOWS_VM
VM_UNIFFI_DIR = UNIFFI_PATH_WINDOWS_VM
VM_SYSTEM32 = "C:\\Windows\\System32"


@asynccontextmanager
async def new_connection(
    ip: str = WINDOWS_1_VM_IP, copy_binaries: bool = False
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
        username="vagrant",
        password="vagrant",  # NOTE: this is hardcoded password for transient vm existing only during the tests
        known_hosts=None,
        options=ssh_options,
    ) as ssh_connection:
        connection = SshConnection(ssh_connection, TargetOS.Windows)

        keys = await _get_network_interface_tunnel_keys(connection)
        for key in keys:
            await connection.create_process(["reg", "delete", key, "/F"]).execute()

        if copy_binaries:
            await _copy_binaries(ssh_connection, connection)
        try:
            yield connection
        finally:
            pass


def _file_copy_progress_handler(
    srcpath, dstpath, bytes_copied, total, file_copy_progress_buffer
) -> None:
    bar_length = 40
    progress_fraction = bytes_copied / total
    progress_block = int(round(bar_length * progress_fraction))
    progress_bar = "#" * progress_block + "-" * (bar_length - progress_block)
    percent_completion = progress_fraction * 100
    progress_message = (
        f"Transferring {srcpath} to {dstpath}: [{progress_bar}] {percent_completion:.2f}% "
        f"({bytes_copied}/{total} bytes)"
    )
    file_copy_progress_buffer.append(progress_message)


async def _copy_file_with_progress_handler(
    ssh_connection, src, dst, allow_missing
) -> None:
    file_copy_progress_buffer: List[str] = []
    try:
        print(datetime.now(), f"Copying files into VM: {src} to {dst}")
        await asyncssh.scp(
            get_root_path(src),
            (ssh_connection, dst),
            progress_handler=lambda srcpath, dsthpath, bytes_copied, total: _file_copy_progress_handler(
                srcpath, dsthpath, bytes_copied, total, file_copy_progress_buffer
            ),
        )
        print(datetime.now(), "Copy succeeded")
    except FileNotFoundError as exception:
        if not allow_missing or str(exception).find(src) < 0:
            print(datetime.now(), "Copy failed", str(exception))
            raise exception

        print(
            datetime.now(),
            "Copy failed",
            str(exception),
            "but it is allowed to fail",
        )
    except Exception as e:
        print("\n".join(file_copy_progress_buffer))
        print(datetime.now(), "Copy failed", str(e))
        raise e


async def _copy_binaries(
    ssh_connection: asyncssh.SSHClientConnection, connection: Connection
) -> None:
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
        await _copy_file_with_progress_handler(ssh_connection, src, dst, allow_missing)


async def _get_network_interface_tunnel_keys(connection):
    result = await connection.create_process([
        "reg",
        "query",
        "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Class\\{4d36e972-e325-11ce-bfc1-08002be10318}",
        "/s",
        "/f",
        "DriverDesc",
    ]).execute()

    lines = result.get_stdout().splitlines()
    keys = []
    for i, line in enumerate(lines):
        if "WireGuard Tunnel" in line or "Wintun Userspace Tunnel" in line:
            keys.append(lines[i - 1])
    return keys
