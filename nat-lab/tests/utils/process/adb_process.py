import shlex
from .docker_process import DockerProcess
from aiodocker.containers import DockerContainer
from typing import List, Optional


class AdbProcess(DockerProcess):
    """A command run on the Android guest, exec'd as
    `adb -s <serial> shell su 0 sh -c '<cmd>'` inside the emulator's backing
    container.

    Mechanically a DockerProcess - same exec, streaming and teardown (the
    KILL_ID kill script terminates the in-container `adb` client, which ends the
    guest command behind it). This class only adds the adb-shell shaping (the
    part that makes it not just a container process); the caller passes the
    plain guest argv. Run as root via `su 0` (not `adb root`, which restarts
    adbd and drops the bridged interface).
    """

    def __init__(
        self,
        container: DockerContainer,
        container_name: str,
        serial: str,
        command: List[str],
        kill_id=None,
        extra_path: Optional[str] = None,
    ) -> None:
        # adb passes a single string to the device shell, so quote each arg and
        # join. `extra_path` is appended to PATH (so the system/toybox tools keep
        # priority and Termux's baked binaries resolve only as a fallback).
        guest_cmd = " ".join(shlex.quote(arg) for arg in command)
        if extra_path:
            guest_cmd = f'export PATH="$PATH":{shlex.quote(extra_path)}; {guest_cmd}'
        shell_cmd = f"su 0 sh -c {shlex.quote(guest_cmd)}"
        adb_command = ["adb", "-s", serial, "shell", shell_cmd]
        super().__init__(container, container_name, adb_command, kill_id)
