import asyncio
import os
import secrets
import subprocess
from asyncio import Event, wait_for
from contextlib import asynccontextmanager, AsyncExitStack
from datetime import datetime
from tests.utils.connection import TargetOS, Connection
from tests.utils.connection_util import ConnectionTag
from tests.utils.logger import log
from tests.utils.output_notifier import OutputNotifier
from tests.utils.process import Process, ProcessExecError
from tests.utils.testing import get_current_test_log_path
from typing import AsyncIterator, Optional

PCAP_FILE_PATH = {
    TargetOS.Linux: "/dump.pcap",
    TargetOS.Mac: "/var/root/dump.pcap",
    TargetOS.Windows: "C:\\workspace\\dump.pcap",
}
PKTMON_LOG_FILE_WINDOWS = "C:\\workspace\\pktmon.etl"
# pktmon logs to a circular buffer: once the file is full, new packets
# overwrite the oldest ones. The default cap (512 MB) could rotate away the
# start of traffic-heavy captures, so raise it to a size no test should ever
# reach, while still leaving plenty of headroom on the VM disk (~56 GB free)
# so a runaway capture cannot fill it.
PKTMON_MAX_LOG_SIZE_MB = 16 * 1024
TCPDUMP_START_EVENT_TIMEOUT_S = 10


class TcpDump:
    """tcpdump-based packet capture for Linux and Mac; use PktmonCapture on Windows."""

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
        assert (
            connection.target_os != TargetOS.Windows
        ), "tcpdump is not available on Windows, use PktmonCapture instead"
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


class PktmonCapture:
    """Packet capture for Windows VMs built on `pktmon` (in-box since Windows 10 2004).

    - captures on all network adapters present when the capture starts
    - captures full packet payloads (pktmon truncates to 128 bytes by default)
    - no third-party capture driver needed on the VM
    - `pktmon stop` flushes synchronously

    Limitations compared to tcpdump:
    - pktmon enumerates adapters once, at session start, so adapters created
      later are NOT captured. In particular libtelio's wintun/wireguard
      adapter is created after the capture starts, which means decrypted
      tunnel-inner traffic is missing from Windows pcaps (unlike Linux/Mac,
      where `tcpdump -i any` picks up new interfaces). The encrypted tunnel
      traffic is still captured on the physical NICs, and the decrypted
      flows are visible in the counterpart node's pcap (VPN server, DERP,
      peer). Verified empirically; `--comp all` and `netsh trace` have the
      same limitation, and pktmon allows only one session per machine, so
      this cannot be fixed without rolling the session after the adapter
      appears.
    - pktmon only supports inclusive 5-tuple filters, so BPF expressions,
      packet-count limits and the "not port 22" SSH exclusion cannot be
      expressed at capture time; the SSH control channel is instead stripped
      from the pcap on the test runner right after download (see
      strip_ssh_from_pcap())
    - only one pktmon session can run per machine, so leftover sessions are
      stopped before starting a new one

    The .etl log is converted on the VM to a Wireshark-compatible pcapng file
    at PCAP_FILE_PATH once the capture stops, so the download/cleanup flow is
    shared with the other platforms.
    """

    connection: Connection
    output_file: str

    def __init__(
        self, connection: Connection, output_file: Optional[str] = None
    ) -> None:
        assert connection.target_os == TargetOS.Windows
        self.connection = connection
        self.output_file = output_file or PCAP_FILE_PATH[TargetOS.Windows]

    async def _exec_quiet(self, command: list[str], ignore_failure: bool) -> None:
        try:
            await self.connection.create_process(command, quiet=True).execute()
        except ProcessExecError as e:
            if not ignore_failure:
                raise
            log.debug(
                "[%s] '%s' failed (ignored): %s",
                self.connection.tag,
                " ".join(command),
                e.stderr or e.stdout,
            )

    @asynccontextmanager
    async def run(self) -> AsyncIterator["PktmonCapture"]:
        start_time = datetime.now()
        # Only one pktmon session can exist per machine; clean up leftovers
        # from previous (possibly crashed) runs along with stale filters.
        await self._exec_quiet(["pktmon", "stop"], ignore_failure=True)
        await self._exec_quiet(["pktmon", "filter", "remove"], ignore_failure=True)
        await self._exec_quiet(
            [
                "pktmon",
                "start",
                "--capture",
                "--comp",
                "nics",
                "--pkt-size",
                "0",
                "--log-mode",
                "circular",
                "--file-size",
                str(PKTMON_MAX_LOG_SIZE_MB),
                "--file-name",
                PKTMON_LOG_FILE_WINDOWS,
            ],
            ignore_failure=False,
        )
        log.info(
            "[%s] pktmon capture ready in %s",
            self.connection.tag,
            datetime.now() - start_time,
        )
        try:
            yield self
        finally:
            try:
                await self._exec_quiet(["pktmon", "stop"], ignore_failure=False)
                await self._exec_quiet(
                    [
                        "pktmon",
                        "etl2pcap",
                        PKTMON_LOG_FILE_WINDOWS,
                        "--out",
                        self.output_file,
                    ],
                    ignore_failure=False,
                )
            except ProcessExecError as e:
                log.warning(
                    "[%s] failed to stop/convert pktmon capture: %s",
                    self.connection.tag,
                    e.stderr or e.stdout,
                )


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
    if target_os not in [TargetOS.Linux, TargetOS.Mac]:
        raise ValueError(
            f"tcpdump is not supported on {target_os}, use PktmonCapture on Windows"
        )

    if using_sudo:
        command = ["sudo"]
    else:
        command = []
    command += ["tcpdump", "-n"]

    if output_file:
        command += ["-w", output_file]
    else:
        command += ["-w", PCAP_FILE_PATH[target_os]]

    if interfaces:
        command += ["-i", ",".join(interfaces)]
    else:
        command += ["-i", "any"]

    if count:
        command += ["-c", str(count)]

    if flags:
        command += flags

    filter_parts: list[str] = []
    if not include_ssh:
        command += ["--immediate-mode"]
        filter_parts.append("port not 22")
    if expressions:
        filter_parts.extend(expressions)
    if filter_parts:
        command += [" and ".join(f"({p})" for p in filter_parts)]

    return command


async def strip_ssh_from_pcap(pcap_path: str) -> None:
    """Rewrite 'pcap_path' without the port-22 SSH control-channel traffic.

    pktmon cannot exclude traffic at capture time, so Windows captures
    include the test harness's own SSH chatter, which can dominate the pcap
    size. Local tcpdump reads the file without root, so filter it on the
    test runner right after download. Best-effort: on any failure the
    original file is kept.
    """
    if not os.path.isfile(pcap_path):
        return
    filtered_path = f"{pcap_path}.filtered"
    try:
        process = await asyncio.create_subprocess_exec(
            "tcpdump",
            "-r",
            pcap_path,
            "-w",
            filtered_path,
            "port not 22",
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        _, stderr = await process.communicate()
        if process.returncode == 0:
            os.replace(filtered_path, pcap_path)
        else:
            log.warning(
                "Failed to strip SSH traffic from %s, keeping it unfiltered: %s",
                pcap_path,
                stderr.decode(errors="replace"),
            )
    except OSError as e:
        log.warning(
            "Failed to strip SSH traffic from %s, keeping it unfiltered: %s",
            pcap_path,
            e,
        )
    finally:
        if os.path.isfile(filtered_path):
            os.remove(filtered_path)


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


async def _start_capture(
    exit_stack: AsyncExitStack, conn: Connection, session: bool
) -> None:
    for attempt in range(1, 4):
        try:
            if conn.target_os == TargetOS.Windows:
                await exit_stack.enter_async_context(PktmonCapture(conn).run())
            else:
                await exit_stack.enter_async_context(
                    TcpDump(conn, session=session).run()
                )
            return
        except Exception as e:  # pylint: disable=broad-exception-caught
            log.warning(
                "Failed to start packet capture on %s (attempt %d/3): %s",
                conn.tag,
                attempt,
                e,
            )
            if attempt >= 3:
                if conn.target_os == TargetOS.Windows:
                    # Packet capture on Windows is best-effort diagnostics:
                    # a broken capture tool must not fail the test itself
                    # (capture on Windows already had to be disabled once for
                    # destabilizing the VMs, see LLT-5942).
                    log.error("Continuing without packet capture on %s", conn.tag)
                else:
                    raise e


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
                await _start_capture(exit_stack, conn, session)
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

                if conn.target_os == TargetOS.Windows:
                    await strip_ssh_from_pcap(path)

                if conn.target_os in [TargetOS.Linux, TargetOS.Mac]:
                    await conn.create_process(
                        ["rm", "-f", PCAP_FILE_PATH[conn.target_os]], quiet=True
                    ).execute()
                else:
                    await conn.create_process(
                        [
                            "del",
                            PCAP_FILE_PATH[conn.target_os],
                            PKTMON_LOG_FILE_WINDOWS,
                        ],
                        quiet=True,
                    ).execute()
