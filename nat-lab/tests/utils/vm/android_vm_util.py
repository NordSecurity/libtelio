import os
from tests.config import ANDROID_DEVICE_TMP, UNIFFI_PATH_VM_ANDROID
from tests.utils.connection.adb_connection import AdbConnection

# Where the libtelio runtime files land on the guest (inside Termux).
WORK_DIR = UNIFFI_PATH_VM_ANDROID.rstrip("/")

# The libtelio repo is mounted into the container at /libtelio (see the
# android-client-01 volumes), so the files are read straight from the mount and
# `adb push`ed - no host->container copy, same as the other nat-lab containers.
_MOUNT = "/libtelio"
_DIST_ANDROID = (
    f"{_MOUNT}/dist/android/{os.getenv('TELIO_BIN_PROFILE', 'release')}/x86_64"
)
_UNIFFI = f"{_MOUNT}/nat-lab/tests/uniffi"
_BIN = f"{_MOUNT}/nat-lab/bin/android"


async def copy_binaries(connection: AdbConnection) -> None:
    """Push the libtelio runtime onto the Android guest from the mounted repo.

    Termux's home is app-private, so files are first `adb push`ed to
    /data/local/tmp (adb-writable) and then copied into the Termux work dir via
    `run-as`. The launcher (natlab-python) stays in /data/local/tmp where the
    adb-shell user can exec it.
    """
    # (mounted source, filename on device) - the bionic .so plus the python
    # bindings and the Pyro5 remote. telio_bindings.py is platform-agnostic; it
    # must match the .so version (same CI pipeline produces both).
    runtime_files = [
        (f"{_DIST_ANDROID}/libtelio.so", "libtelio.so"),
        (f"{_UNIFFI}/telio_bindings.py", "telio_bindings.py"),
        (f"{_UNIFFI}/libtelio_remote.py", "libtelio_remote.py"),
        (f"{_UNIFFI}/serialization.py", "serialization.py"),
    ]

    for src, name in runtime_files:
        await connection.push_from_container(src, f"{ANDROID_DEVICE_TMP}{name}")

    copy_cmd = f"mkdir -p {WORK_DIR} && " + " && ".join(
        f"cp {ANDROID_DEVICE_TMP}{name} {WORK_DIR}/{name}" for _, name in runtime_files
    )
    await connection.termux_process(copy_cmd, quiet=True).execute()

    # Launcher that re-execs into the Termux python (see bin/android/natlab-python).
    await connection.push_from_container(
        f"{_BIN}/natlab-python", f"{ANDROID_DEVICE_TMP}natlab-python"
    )
    await connection.create_process(
        ["chmod", "755", f"{ANDROID_DEVICE_TMP}natlab-python"], quiet=True
    ).execute()
