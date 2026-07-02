import asyncio
import shlex
from .docker_process import (
    DockerProcess,
    _EXIT_CODE_SIGKILL,
    _EXIT_CODE_SIGTERM,
    generate_kill_id,
)
from .process import ProcessExecError, StreamCallback
from aiodocker.containers import DockerContainer
from contextlib import asynccontextmanager
from tests.utils.logger import log
from typing import AsyncIterator, List, Optional

_GUEST_KILL_TIMEOUT = 10.0

# Killing the in-container adb client can orphan the `su 0` child on the guest,
# leaking the tool (ping/iperf3/nc/...). Single grep pass to find candidates,
# then a NUL-anchored exact match per candidate (mirrors
# bin/kill_process_by_natlab_id) so one id can never match another's KILL_ID.
_GUEST_KILL_SCRIPT = (
    'id="$1"; [ -n "$id" ] || exit 2; killed=""; '
    'for f in $(grep -alF "KILL_ID=$id" /proc/[0-9]*/environ 2>/dev/null); do '
    'tr "\\000" "\\n" < "$f" 2>/dev/null | grep -qxF "KILL_ID=$id" || continue; '
    'pid="${f#/proc/}"; pid="${pid%/environ}"; '
    'kill "$pid" 2>/dev/null && killed="$killed $pid"; '
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
        # Fix the id now so we can export it into the *guest* env; DockerProcess
        # only sets KILL_ID on the in-container adb client, which the guest never
        # sees.
        kill_id = kill_id or generate_kill_id()
        self._serial = serial
        # adb passes a single string to the device shell, so quote+join each arg.
        # extra_path is appended (not prepended) so system/toybox tools keep
        # priority and Termux's baked binaries resolve only as a fallback.
        guest_cmd = " ".join(shlex.quote(arg) for arg in command)
        guest_cmd = f"export KILL_ID={shlex.quote(kill_id)}; {guest_cmd}"
        if extra_path:
            guest_cmd = f'export PATH="$PATH":{shlex.quote(extra_path)}; {guest_cmd}'
        shell_cmd = f"su 0 sh -c {shlex.quote(guest_cmd)}"
        adb_command = ["adb", "-s", serial, "shell", shell_cmd]
        super().__init__(container, container_name, adb_command, kill_id)

    async def _kill_guest_process(self) -> None:
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
            try:
                stdout, stderr = await asyncio.wait_for(
                    proc.communicate(), timeout=_GUEST_KILL_TIMEOUT
                )
            except asyncio.TimeoutError:
                proc.kill()
                raise
            out = (stdout or b"").decode(errors="replace").strip()
            if proc.returncode != 0:
                log.warning(
                    "[%s] guest kill-by-id failed (rc=%s): %s",
                    self._container_name,
                    proc.returncode,
                    out + " " + (stderr or b"").decode(errors="replace").strip(),
                )
            elif out.startswith("killed:"):
                log.info(
                    "[%s] guest kill-by-id terminated pid(s)%s (KILL_ID=%s)",
                    self._container_name,
                    out[len("killed:") :],
                    self._kill_id,
                )
        except Exception as e:  # pylint: disable=broad-exception-caught
            log.warning(
                "[%s] guest kill-by-id failed (ignored): %s", self._container_name, e
            )

    async def _kill_exec_if_running(self) -> None:
        # Guest kill must precede the base kill (ending the adb client exec is
        # what orphans the su child) and is gated the same way as the base one:
        # only while the exec is still running. Inspect failures are swallowed
        # here because super() re-runs the same checks and logs/raises itself.
        try:
            exec_alive = (await self._wait_for_process_start())["ExitCode"] is None
        except (asyncio.TimeoutError, RuntimeError):
            exec_alive = False
        if exec_alive:
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
