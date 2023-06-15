from utils.connection import Connection, SshConnection, TargetOS
from utils.process import ProcessExecError
from config import get_root_path
from contextlib import asynccontextmanager
from typing import AsyncIterator
import asyncssh
import config
import subprocess


VM_TCLI_DIR = "C:\\workspace\\binaries"
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
        password="vagrant",
        known_hosts=None,
        options=ssh_options,
    ) as ssh_connection:
        connection = SshConnection(ssh_connection)
        connection.target_os = TargetOS.Windows

        await _copy_binaries(ssh_connection, connection)
        await _disable_firewall(connection)

        try:
            yield connection
        finally:
            await _kill_processes(connection)


async def _disable_firewall(connection: Connection):
    await connection.create_process(
        ["netsh", "advfirewall", "set", "allprofiles", "state", "off"]
    ).execute()


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


async def _kill_processes(connection: Connection) -> None:
    processes = ["tcli", "derpcli", "ping", "stunclient", "iperf3"]
    for proc in processes:
        try:
            await connection.create_process(
                ["taskkill", "/IM", f"{proc}.exe", "/F"]
            ).execute()
        except ProcessExecError as exception:
            if exception.stderr.find(f'The process "{proc}.exe" not found') < 0:
                raise exception
