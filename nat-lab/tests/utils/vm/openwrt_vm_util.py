import asyncssh
from config import get_root_path
from utils.connection import Connection
from utils.process import ProcessExecError

NATLAB_BIN_PATH = "nat-lab/bin/"
NATLAB_DATA_PATH = "nat-lab/data/"
LOCAL_BIN_DIR = "/tmp/"
OWR_CERT_PATH = "/etc/ssl/server_certificate/"
NORDVPNLITE_OWR_NAME = "nordvpnlite_x86_64.ipk"
CERT_FILE_NAME = "test.pem"


async def copy_binaries(
    ssh_connection: asyncssh.SSHClientConnection, connection: Connection
) -> None:

    try:
        await connection.create_process(["mkdir", "-p", f"{OWR_CERT_PATH}"]).execute()
    except ProcessExecError as e:
        raise RuntimeError(f"Failed to create remote dir {e.stderr}") from e

    files_to_copy = [
        (
            f"{NATLAB_BIN_PATH}{NORDVPNLITE_OWR_NAME}",
            f"{LOCAL_BIN_DIR}{NORDVPNLITE_OWR_NAME}",
        ),
        (
            f"{NATLAB_DATA_PATH}core_api/{CERT_FILE_NAME}",
            f"{OWR_CERT_PATH}{CERT_FILE_NAME}",
        ),
    ]
    for src, dst in files_to_copy:
        await asyncssh.scp(
            get_root_path(src),
            (ssh_connection, dst),
        )

    try:
        await connection.create_process(
            ["opkg", "install", f"{LOCAL_BIN_DIR}{NORDVPNLITE_OWR_NAME}"]
        ).execute()
    except ProcessExecError as e:
        raise RuntimeError(f"opkg install failed: {e.stderr}") from e
