from .connection import Connection, TargetOS, ConnectionTag, setup_ephemeral_ports
from .docker_connection import backing_container_id
from aiodocker import Docker
from aiodocker.containers import DockerContainer
from asyncio import to_thread
from contextlib import asynccontextmanager
from logging import DEBUG, INFO
from subprocess import run, DEVNULL
from tests.utils.logger import log
from tests.utils.process import AdbProcess, DockerProcess, Process
from typing import List, AsyncIterator
from uuid import uuid4

# The emulator AVD is named "natlab" in the android-emulator-docker image; adb
# sees it on the default console port, hence the fixed serial.
DEFAULT_ADB_SERIAL = "emulator-5554"

# Scratch dir inside the backing container used to stage files for adb push/pull.
_CONTAINER_STAGE_DIR = "/tmp/adb-stage"

# Termux (the bionic python + Pyro5 runtime) lives in app-private storage.
TERMUX_PREFIX = "/data/data/com.termux/files/usr"
TERMUX_HOME = "/data/data/com.termux/files/home"
TERMUX_PACKAGE = "com.termux"

# Environment a Termux command needs (the app sets this up at login; we replicate
# it for non-interactive `run-as` invocations). Keep in sync with the equivalent
# exports in bin/android/natlab-python (the root/exec variant of the same env).
_TERMUX_ENV = (
    f"export PREFIX={TERMUX_PREFIX} HOME={TERMUX_HOME} "
    f'PATH="{TERMUX_PREFIX}/bin:$PATH" LD_LIBRARY_PATH={TERMUX_PREFIX}/lib '
    f"LD_PRELOAD={TERMUX_PREFIX}/lib/libtermux-exec.so TMPDIR={TERMUX_PREFIX}/tmp; "
)


class AdbConnection(Connection):
    """Connection to an Android emulator guest.

    The emulator (and its adb server) run inside a docker container; the guest
    itself sits behind the emulator's user-mode NAT and is not directly
    addressable. So instead of talking to the guest over the network, we exec
    `adb ... shell` *inside* the backing container (reusing DockerProcess) and
    let adb relay to the guest.
    """

    _container: DockerContainer
    _connection_id: str
    _serial: str

    def __init__(
        self,
        container: DockerContainer,
        tag: ConnectionTag,
        serial: str = DEFAULT_ADB_SERIAL,
    ):
        # The Android shell is a toybox/Linux userland (AdbProcess uses
        # shlex.quote); routing/binaries differ, hence its own TargetOS +
        # AndroidRouter.
        super().__init__(TargetOS.Android, tag)
        self._container = container
        self._connection_id = str(uuid4())
        self._serial = serial

    async def __aenter__(self):
        log.info(
            "[%s] ADB connection opened (conn_id=%s)",
            self.tag.name,
            self._connection_id,
        )
        await setup_ephemeral_ports(self)
        return self

    async def __aexit__(self, *_):
        log.info(
            "[%s] ADB connection closed (conn_id=%s)",
            self.tag.name,
            self._connection_id,
        )

    @classmethod
    @asynccontextmanager
    async def new_connection(
        cls,
        docker: Docker,
        tag: ConnectionTag,
        serial: str = DEFAULT_ADB_SERIAL,
        copy_binaries: bool = False,
    ) -> AsyncIterator["AdbConnection"]:
        container = await docker.containers.get(backing_container_id(tag))
        async with cls(container, tag, serial) as connection:
            if copy_binaries:
                await connection.copy_binaries()
            yield connection

    async def copy_binaries(self) -> None:
        import tests.utils.vm.android_vm_util as utils_android  # pylint: disable=import-outside-toplevel

        await utils_android.copy_binaries(self)

    def termux_process(self, script: str, quiet: bool = False) -> "Process":
        """Run a shell script inside Termux (bionic python + libtelio runtime)."""
        return self.create_process(
            [
                "run-as",
                TERMUX_PACKAGE,
                f"{TERMUX_PREFIX}/bin/sh",
                "-c",
                _TERMUX_ENV + script,
            ],
            quiet=quiet,
        )

    async def push_from_container(self, container_path: str, device_path: str) -> None:
        """`adb push` a file already present in the backing container (e.g. via
        the /libtelio repo mount) to the device - no host->container copy."""
        await self._docker_exec(
            ["adb", "-s", self._serial, "push", container_path, device_path]
        ).execute()

    async def push_to_device(self, local_host_path: str, device_path: str) -> None:
        """Stage a host file into the backing container, then `adb push` to the
        device. `device_path` must be adb-writable (e.g. under /data/local/tmp)."""
        staged = f"{_CONTAINER_STAGE_DIR}/{device_path.rsplit('/', 1)[-1]}"
        await self._docker_exec(["mkdir", "-p", _CONTAINER_STAGE_DIR]).execute()

        def cp_in():
            run(
                [
                    "docker",
                    "cp",
                    local_host_path,
                    f"{backing_container_id(self.tag)}:{staged}",
                ],
                stdout=DEVNULL,
                stderr=DEVNULL,
                check=True,
            )

        await to_thread(cp_in)
        await self._docker_exec(
            ["adb", "-s", self._serial, "push", staged, device_path]
        ).execute()

    def create_process(
        self, command: List[str], kill_id=None, term_type=None, quiet=False
    ) -> "Process":
        log.log(
            DEBUG if quiet else INFO,
            "[%s] Executing %s",
            self.tag.name,
            " ".join(command),
        )
        # AdbProcess wraps this into `adb shell su 0 ...`; Termux's bin is added
        # to PATH so baked tools (tcpdump, stunclient) resolve by bare name.
        return AdbProcess(
            self._container,
            backing_container_id(self.tag),
            self._serial,
            command,
            kill_id,
            extra_path=f"{TERMUX_PREFIX}/bin",
        )

    def _docker_exec(self, command: List[str]) -> "Process":
        """Run a command in the backing container itself (not on the guest, so a
        plain DockerProcess) - used for adb push/pull and staging."""
        return DockerProcess(
            self._container, backing_container_id(self.tag), command, None
        )

    async def get_ip_address(self) -> tuple[str, str]:
        # The guest is bridged onto the docker network with its own IP (distinct
        # from the container's helper IP), so report the guest's LAN address -
        # this is what a Pyro5 proxy connects to.
        from tests.config import LAN_ADDR_MAP  # pylint: disable=import-outside-toplevel

        guest_ip = LAN_ADDR_MAP[self.tag]["primary"]
        return (guest_ip, guest_ip)

    async def upload_file(self, local_file_path: str, remote_file_path: str) -> None:
        """Stage the file into the backing container, then `adb push` to guest."""
        await self.push_to_device(local_file_path, remote_file_path)

    async def download(self, remote_path: str, local_path: str) -> None:
        """`adb pull` from guest into the backing container, then docker cp out."""
        staged = f"{_CONTAINER_STAGE_DIR}/{remote_path.rsplit('/', 1)[-1]}"
        await self._docker_exec(["mkdir", "-p", _CONTAINER_STAGE_DIR]).execute()
        await self._docker_exec(
            ["adb", "-s", self._serial, "pull", remote_path, staged]
        ).execute()

        def cp_out():
            run(
                [
                    "docker",
                    "cp",
                    f"{backing_container_id(self.tag)}:{staged}",
                    local_path,
                ],
                stdout=DEVNULL,
                stderr=DEVNULL,
                check=False,
            )

        await to_thread(cp_out)
