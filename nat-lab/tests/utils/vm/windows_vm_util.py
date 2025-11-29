import asyncssh
import os
from tests.config import (
    get_root_path,
    LIBTELIO_BINARY_PATH_WINDOWS_VM,
    UNIFFI_PATH_WINDOWS_VM,
)
from tests.utils.connection import Connection
from tests.utils.logger import log
from tests.utils.process import ProcessExecError
from typing import List

VM_TCLI_DIR = LIBTELIO_BINARY_PATH_WINDOWS_VM
VM_UNIFFI_DIR = UNIFFI_PATH_WINDOWS_VM
VM_SYSTEM32 = "C:\\Windows\\System32"


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
        log.info("Copying files into VM: %s to %s", src, dst)
        await asyncssh.scp(
            get_root_path(src),
            (ssh_connection, dst),
            progress_handler=lambda srcpath, dsthpath, bytes_copied, total: _file_copy_progress_handler(
                srcpath, dsthpath, bytes_copied, total, file_copy_progress_buffer
            ),
        )
        log.info("Copy succeeded")
    except FileNotFoundError as exception:
        if not allow_missing or str(exception).find(src) < 0:
            log.error("Copy failed %s", str(exception))
            raise exception

        log.warning(
            "Copy failed but it is allowed to fail",
        )
    except Exception as e:
        log.error("\n".join(file_copy_progress_buffer))
        log.error("Copy failed %s", str(e))
        raise e


async def copy_binaries(
    ssh_connection: asyncssh.SSHClientConnection, connection: Connection
) -> None:
    for directory in [VM_TCLI_DIR, VM_UNIFFI_DIR]:
        try:
            await connection.create_process(
                ["rmdir", "/s", "/q", directory], quiet=True
            ).execute()
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

    DIST_DIR = f"dist/windows/{os.getenv('TELIO_BIN_PROFILE')}/x86_64/"
    LOCAL_UNIFFI_DIR = "nat-lab/tests/uniffi/"
    LOCAL_BIN_DIR = "nat-lab/bin/"

    files_to_copy = [
        (f"{DIST_DIR}*", VM_TCLI_DIR, False),
        (f"{LOCAL_UNIFFI_DIR}telio_bindings.py", VM_UNIFFI_DIR, False),
        (f"{LOCAL_UNIFFI_DIR}libtelio_remote.py", VM_UNIFFI_DIR, False),
        (f"{LOCAL_UNIFFI_DIR}serialization.py", VM_UNIFFI_DIR, False),
        (f"{DIST_DIR}telio.dll", f"{VM_UNIFFI_DIR}", False),
        (f"{DIST_DIR}sqlite3.dll", VM_UNIFFI_DIR, True),
        (f"{DIST_DIR}wireguard.dll", VM_UNIFFI_DIR, False),
        (f"{DIST_DIR}wintun.dll", VM_SYSTEM32, False),
        (f"{LOCAL_BIN_DIR}multicast.py", VM_TCLI_DIR, False),
    ]

    for src, dst, allow_missing in files_to_copy:
        await _copy_file_with_progress_handler(ssh_connection, src, dst, allow_missing)


async def get_network_interface_tunnel_keys(connection):
    result = await connection.create_process(
        [
            "reg",
            "query",
            "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Class\\{4d36e972-e325-11ce-bfc1-08002be10318}",
            "/s",
            "/f",
            "DriverDesc",
        ],
        quiet=True,
    ).execute()

    lines = result.get_stdout().splitlines()
    keys = []
    for i, line in enumerate(lines):
        if "WireGuard Tunnel" in line or "Wintun Userspace Tunnel" in line:
            keys.append(lines[i - 1])
    return keys
