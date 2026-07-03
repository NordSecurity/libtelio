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

# Guest-side kill-by-id: the base kill only reaches the adb client, orphaning the
# `su 0` child. NUL-anchored exact match so one id can't match another's KILL_ID.
_GUEST_KILL_SCRIPT = (
    'id="$1"; [ -n "$id" ] || exit 2; killed=""; '
    'for f in $(grep -alF "KILL_ID=$id" /proc/[0-9]*/environ 2>/dev/null); do '
    'tr "\\000" "\\n" < "$f" 2>/dev/null | grep -qxF "KILL_ID=$id" || continue; '
    'pid="${f#/proc/}"; pid="${pid%/environ}"; '
    'kill "$pid" 2>/dev/null && killed="$killed $pid"; '
    'done; [ -n "$killed" ] && echo "killed:$killed"; exit 0'
)


class AdbProcess(DockerProcess):
    """A command on the Android guest, run as root:
        adb -s <serial> shell su 0 sh -c '<cmd>'
    `su 0` not `adb root` (adb root restarts adbd, dropping the bridged interface).
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
        # export KILL_ID into the guest env (base only sets it on the adb client)
        kill_id = kill_id or generate_kill_id()
        self._serial = serial
        guest_cmd = " ".join(shlex.quote(arg) for arg in command)
        guest_cmd = f"export KILL_ID={shlex.quote(kill_id)}; {guest_cmd}"
        # append (not prepend): system/toybox tools win, Termux binaries are fallback
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
            stdout, stderr = await proc.communicate()
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
        # kill the guest process before the base ends the adb command (that
        # orphans the su child)
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
        # teardown makes adb exit by signal (137/143); tolerate it for this exec,
        # but don't mask a real superseded error
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
