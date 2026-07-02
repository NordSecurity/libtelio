import shlex
from .docker_process import DockerProcess, _EXIT_CODE_SIGKILL, _EXIT_CODE_SIGTERM
from .process import ProcessExecError, StreamCallback
from aiodocker.containers import DockerContainer
from contextlib import asynccontextmanager
from tests.utils.logger import log
from typing import AsyncIterator, List, Optional


class AdbProcess(DockerProcess):
    """A command run on the Android guest, exec'd as
    `adb -s <serial> shell su 0 sh -c '<cmd>'` inside the emulator's backing
    container.

    Mechanically a DockerProcess - same exec and streaming. This class adds the
    adb-shell shaping (the part that makes it not just a container process); the
    caller passes the plain guest argv. Run as root via `su 0` (not `adb root`,
    which restarts adbd and drops the bridged interface).

    Teardown differs from the base: the guest daemon shuts itself down and the
    adb client is torn down with it, so adb reports the exec exit as a signal
    (137/143) and the base class never gets to flag it as an intentional kill
    (_kill_sent). `run` tolerates that teardown signal-exit - see its comment.
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

    @asynccontextmanager
    async def run(
        self,
        stdout_callback: Optional[StreamCallback] = None,
        stderr_callback: Optional[StreamCallback] = None,
        privileged: bool = False,
    ) -> AsyncIterator["AdbProcess"]:
        # On teardown the `adb shell` exec is killed by a signal (the guest
        # daemon stops itself / the adb client is torn down with it) and adb
        # surfaces 137/143 as the exec exit; because the guest self-exits, the
        # base class can't record it as an intentional kill (_kill_sent), so it
        # raises. This is the same teardown signal-exit the base DockerProcess
        # already tolerates on docker - swallow it for this exec only, but never
        # mask a real exception it superseded.
        try:
            async with super().run(stdout_callback, stderr_callback, privileged):
                yield self
        except ProcessExecError as e:
            if e.cmd is not self._command or e.returncode not in (
                _EXIT_CODE_SIGKILL,
                _EXIT_CODE_SIGTERM,
            ):
                raise
            superseded = e.__context__
            if superseded is not None:
                raise superseded
            log.debug(
                "[%s] adb exec exited %d on teardown (expected)",
                self._container_name,
                e.returncode,
            )
