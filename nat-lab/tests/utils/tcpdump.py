import asyncio
import os
import secrets
import subprocess
from asyncio import Event, wait_for, sleep
from contextlib import asynccontextmanager, AsyncExitStack
from datetime import datetime
from tests.config import WINDUMP_BINARY_WINDOWS
from tests.utils.connection import TargetOS, Connection
from tests.utils.connection_util import ConnectionTag
from tests.utils.logger import log
from tests.utils.output_notifier import OutputNotifier
from tests.utils.process import Process
from tests.utils.testing import get_current_test_log_path
from typing import AsyncIterator, Optional

PCAP_FILE_PATH = {
    TargetOS.Linux: "/dump.pcap",
    TargetOS.Mac: "/var/root/dump.pcap",
    TargetOS.Windows: "C:\\workspace\\dump.pcap",
}
TCPDUMP_START_EVENT_TIMEOUT_S = 10


class TcpDump:
    interfaces: Optional[list[str]]
    connection: Connection
    process: Process
    command: list[str]
    stdout: str
    stderr: str
    output_file: Optional[str]
    output_notifier: OutputNotifier
    count: Optional[int]

    def __init__(
        self,
        connection: Connection,
        flags: Optional[list[str]] = None,
        expressions: Optional[list[str]] = None,
        interfaces: Optional[list[str]] = None,
        output_file: Optional[str] = None,
        count: Optional[int] = None,
        session: bool = False,
    ) -> None:
        self.connection = connection
        self.interfaces = interfaces
        self.output_file = output_file
        self.output_notifier = OutputNotifier()
        self.start_event = Event()
        self.count = count
        self.stdout = ""
        self.stderr = ""

        self.output_notifier.notify_output("listening on", self.start_event)

        self.command = build_tcpdump_command(
            self.connection.target_os,
            flags,
            expressions,
            self.interfaces,
            self.output_file,
            self.count,
            False,
        )

        self.process = self.connection.create_process(
            self.command,
            # xterm type is needed here, because Mac and Linux VM on default term type doesn't
            # handle signals properly while `tcpdump -w file` is running, without writing
            # to file, everything works fine
            term_type=(
                "xterm"
                if self.connection.tag
                in [
                    ConnectionTag.VM_MAC,
                    ConnectionTag.VM_LINUX_NLX_1,
                    ConnectionTag.VM_LINUX_FULLCONE_GW_1,
                    ConnectionTag.VM_LINUX_FULLCONE_GW_2,
                ]
                else None
            ),
            kill_id="DO_NOT_KILL" + secrets.token_hex(8).upper() if session else None,
            quiet=True,
        )

    def get_stdout(self) -> str:
        return self.stdout

    def get_stderr(self) -> str:
        return self.stderr

    async def on_stdout(self, output: str) -> None:
        log.debug("tcpdump: %s", output)
        self.stdout += output
        await self.output_notifier.handle_output(output)

    async def on_stderr(self, output: str) -> None:
        log.debug("tcpdump err: %s", output)
        self.stderr += output
        await self.output_notifier.handle_output(output)

    async def execute(self) -> None:
        try:
            await self.process.execute(self.on_stdout, self.on_stderr, True)
        except Exception as e:
            log.error("Error executing tcpdump: %s", e)
            raise

    @asynccontextmanager
    async def run(self) -> AsyncIterator["TcpDump"]:
        start_time = datetime.now()
        async with self.process.run(self.on_stdout, self.on_stderr, True):
            await wait_for(self.start_event.wait(), TCPDUMP_START_EVENT_TIMEOUT_S)
            delta = datetime.now() - start_time
            log.info(
                "[%s] '%s' time till ready: %s",
                self.connection.tag,
                " ".join(self.command),
                delta,
            )
            yield self
            # Windump takes so long to flush packets to stdout/file
            if self.connection.target_os == TargetOS.Windows:
                await sleep(5)


def build_tcpdump_command(
    target_os: TargetOS,
    flags: Optional[list[str]] = None,
    expressions: Optional[list[str]] = None,
    interfaces: Optional[list[str]] = None,
    output_file: Optional[str] = None,
    count: Optional[int] = None,
    include_ssh: bool = False,
    using_sudo: bool = False,
):
    def get_tcpdump_binary(target_os: TargetOS) -> str:
        if target_os in [TargetOS.Linux, TargetOS.Mac]:
            return "tcpdump"

        if target_os == TargetOS.Windows:
            return WINDUMP_BINARY_WINDOWS

        raise ValueError(f"target_os not supported {target_os}")

    if using_sudo:
        command = ["sudo"]
    else:
        command = []
    command += [get_tcpdump_binary(target_os), "-n"]

    if output_file:
        command += ["-w", output_file]
    else:
        command += ["-w", PCAP_FILE_PATH[target_os]]

    if interfaces:
        if target_os != TargetOS.Windows:
            command += ["-i", ",".join(interfaces)]
        else:
            # TODO(gytsto). Windump itself only supports one interface at the time,
            # but it supports multiple instances of Windump without any issues,
            # so there is a workaround we can do for multiple interfaces:
            # - create multiple process of windump for each interface
            # - when finished with dump, just combine the pcap's with `mergecap` or smth
            log.warning("Currently tcpdump for windows support only 1 interface")
            command += ["-i", interfaces[0]]
    else:
        if target_os != TargetOS.Windows:
            command += ["-i", "any"]
        else:
            command += ["-i", "2"]

    if count:
        command += ["-c", str(count)]

    if flags:
        command += flags

    if not include_ssh:
        if target_os != TargetOS.Windows:
            command += ["--immediate-mode"]
            command += ["port not 22"]
        else:
            command += ["not port 22"]

    if expressions:
        command += expressions

    return command


def find_unique_path_for_tcpdump(log_dir, guest_name):
    candidate_path = f"{log_dir}/{guest_name}.pcap"
    counter = 1
    # NOTE: counter starting from '1' means that the file will either have no suffix or
    # will have a suffix starting from '2'. This is to make it clear that it's not the
    # first log for that guest/client.
    while os.path.isfile(candidate_path):
        counter += 1
        candidate_path = f"./{log_dir}/{guest_name}-{counter}.pcap"
    return candidate_path


@asynccontextmanager
async def make_local_tcpdump():
    target_os = TargetOS.local()
    using_sudo = target_os != TargetOS.Windows and os.geteuid() != 0
    command = build_tcpdump_command(
        target_os,
        None,
        None,
        ["any"],
        "logs/local.pcap",
        None,
        include_ssh=False,
        using_sudo=using_sudo,
    )

    os.makedirs("logs", exist_ok=True)

    process = None
    try:
        process = await asyncio.create_subprocess_exec(
            *command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        yield
    except Exception:
        if process:
            log.error("tcpdump stderr:")
            log.error(process.stderr)
            log.error("tcpdump stdout:")
            log.error(process.stdout)
        raise
    finally:
        if process:
            process.kill()
            await process.wait()


@asynccontextmanager
async def make_tcpdump(
    connection_list: list[Connection],
    download: bool = True,
    store_in: Optional[str] = None,
    session: bool = False,
):
    try:
        async with AsyncExitStack() as exit_stack:
            for conn in connection_list:
                # TODO(LLT-5942): temporary disable windows tcpdump
                if conn.target_os == TargetOS.Windows:
                    continue
                for attempt in range(1, 4):
                    try:
                        await exit_stack.enter_async_context(
                            TcpDump(conn, session=session).run()
                        )
                        break
                    except Exception as e:  # pylint: disable=broad-exception-caught
                        log.warning(
                            "Failed to start tcpdump on %s (attempt %d/3): %s",
                            conn.tag,
                            attempt,
                            e,
                        )
                        if attempt >= 3:
                            raise e
            yield
    finally:
        if download:
            log_dir = get_current_test_log_path()
            os.makedirs(log_dir, exist_ok=True)
            for conn in connection_list:
                path = find_unique_path_for_tcpdump(
                    store_in if store_in else log_dir, conn.tag.name
                )
                await conn.download(PCAP_FILE_PATH[conn.target_os], path)

                if conn.target_os in [TargetOS.Linux, TargetOS.Mac]:
                    await conn.create_process(
                        ["rm", "-f", PCAP_FILE_PATH[conn.target_os]], quiet=True
                    ).execute()
                else:
                    await conn.create_process(
                        ["del", PCAP_FILE_PATH[conn.target_os]]
                    ).execute()
