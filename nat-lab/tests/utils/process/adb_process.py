import asyncio
import secrets
import shlex
from .docker_process import DockerProcess, _EXIT_CODE_SIGKILL, _EXIT_CODE_SIGTERM
from .process import ProcessExecError, StreamCallback
from aiodocker.containers import DockerContainer
from contextlib import asynccontextmanager
from tests.utils.logger import log
from typing import AsyncIterator, List, Optional

# Guest-side analog of bin/kill_process_by_natlab_id. The base class kills the
# in-container adb *client* by KILL_ID, but adb can orphan the `su 0` child on
# the guest when that stream closes, so the actual tool (ping/iperf3/nc/...) would
# leak. Scan the guest's /proc for the matching KILL_ID and kill it. Pure toybox
# sh: glob /proc, grep -a the NUL-separated environ; $1 is the id. Echoes
# "killed:<pids>" so the caller can log what was actually terminated (lets CI
# confirm the guest-side kill is reaching the process, not just no-oping).
_GUEST_KILL_SCRIPT = (
    'id="$1"; [ -n "$id" ] || exit 2; killed=""; '
    "for d in /proc/[0-9]*; do "
    'grep -aq "KILL_ID=$id" "$d/environ" 2>/dev/null || continue; '
    'pid="${d#/proc/}"; kill "$pid" 2>/dev/null && killed="$killed $pid"; '
    'done; [ -n "$killed" ] && echo "killed:$killed"; exit 0'
)


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
        # Fix the id here (mirroring DockerProcess's default) so we can export it
        # into the *guest* env below - DockerProcess only puts KILL_ID on the
        # in-container adb-client exec, which the guest process never sees.
        kill_id = kill_id if kill_id else secrets.token_hex(8).upper()
        self._serial = serial
        # adb passes a single string to the device shell, so quote each arg and
        # join. KILL_ID is exported so the guest process carries it (see
        # _kill_exec_if_running). `extra_path` is appended to PATH (so the
        # system/toybox tools keep priority and Termux's baked binaries resolve
        # only as a fallback).
        guest_cmd = " ".join(shlex.quote(arg) for arg in command)
        guest_cmd = f"export KILL_ID={shlex.quote(kill_id)}; {guest_cmd}"
        if extra_path:
            guest_cmd = f'export PATH="$PATH":{shlex.quote(extra_path)}; {guest_cmd}'
        shell_cmd = f"su 0 sh -c {shlex.quote(guest_cmd)}"
        adb_command = ["adb", "-s", serial, "shell", shell_cmd]
        super().__init__(container, container_name, adb_command, kill_id)

    async def _kill_guest_process(self) -> None:
        """Best-effort: terminate the guest process carrying our KILL_ID."""
        inner = f"su 0 sh -c {shlex.quote(_GUEST_KILL_SCRIPT)} _ {shlex.quote(self._kill_id)}"
        try:
            proc = await asyncio.create_subprocess_exec(
                "docker",
                "exec",
                self._container.id,
                "adb",
                "-s",
                self._serial,
                "shell",
                inner,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await proc.communicate()
            out = (stdout or b"").decode(errors="replace").strip()
            if out.startswith("killed:"):
                log.info(
                    "[%s] guest kill-by-id terminated pid(s)%s (KILL_ID=%s)",
                    self._container_name,
                    out[len("killed:") :],
                    self._kill_id,
                )
        except Exception as e:  # pylint: disable=broad-exception-caught
            log.debug(
                "[%s] guest kill-by-id failed (ignored): %s", self._container_name, e
            )

    async def _kill_exec_if_running(self) -> None:
        # Kill the guest process first (adb may orphan the su child when the exec
        # stream closes), then let the base class kill the in-container adb client
        # to end the exec and record the intentional kill.
        await self._kill_guest_process()
        await super()._kill_exec_if_running()

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
