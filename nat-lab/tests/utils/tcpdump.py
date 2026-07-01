import asyncio
import os
import secrets
import subprocess
from asyncio import Event, wait_for
from contextlib import asynccontextmanager, AsyncExitStack
from datetime import datetime
from tests.config import ANDROID_DEVICE_TMP
from tests.utils.connection import Connection, ConnectionTag, TargetOS
from tests.utils.logger import log
from tests.utils.output_notifier import OutputNotifier
from tests.utils.process import Process, ProcessExecError
from tests.utils.testing import get_current_test_log_path
from typing import AsyncIterator, Optional

PCAP_FILE_PATH = {
    TargetOS.Linux: "/dump.pcap",
    TargetOS.Mac: "/var/root/dump.pcap",
    TargetOS.Windows: "C:\\workspace\\dump.pcap",
    # The Linux default `/dump.pcap` lands on `/`, which is a read-only
    # partition on Android (there's no /tmp). ANDROID_DEVICE_TMP is on the
    # read-write /data partition - the adb scratch dir used elsewhere too.
    TargetOS.Android: f"{ANDROID_DEVICE_TMP}dump.pcap",
}
# Base path for pktmon's .etl logs; one indexed file per capture segment
# (pktmon.0.etl, pktmon.1.etl, ...) - see PktmonCapture for why we roll.
PKTMON_LOG_FILE_WINDOWS = "C:\\workspace\\pktmon.etl"
# Circular-buffer cap, raised from the 512 MB default so long captures don't
# rotate away their start (VM has ~56 GB free).
PKTMON_MAX_LOG_SIZE_MB = 16 * 1024
# How often to check for adapters that appeared after capture start (e.g.
# libtelio's tunnel adapter), and a safety cap on how many times we roll.
PKTMON_ADAPTER_POLL_INTERVAL_S = 1.0
PKTMON_MAX_SEGMENTS = 8
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


def _with_segment_index(path: str, segment: int) -> str:
    base, dot, ext = path.rpartition(".")
    return f"{base}.{segment}.{ext}" if dot else f"{path}.{segment}"


class PktmonCapture:
    """Packet capture for Windows VMs using the in-box `pktmon` tool.

    `--comp all` captures libtelio's virtual tunnel adapter (`--comp nics`
    misses it). pktmon only enumerates adapters at session start, so when the
    tunnel adapter appears later we roll the session (stop+start) to pick it up
    (LLT-7429), splitting capture into .etl/pcap segments. Segments are merged
    and normalised after download (see merge_windows_pcaps). Best-effort:
    depends on the tunnel adapter living long enough for the roll to fire.
    """

    connection: Connection
    output_file: str
    # pcap segments produced on the VM (only ones that converted), in order
    output_files: list[str]
    # all .etl logs to clean up afterwards
    log_files: list[str]

    def __init__(
        self, connection: Connection, output_file: Optional[str] = None
    ) -> None:
        assert connection.target_os == TargetOS.Windows
        self.connection = connection
        self.output_file = output_file or PCAP_FILE_PATH[TargetOS.Windows]
        self._segment = 0
        self._baseline: set[str] = set()
        self.output_files = []
        self.log_files = []

    def _etl_path(self, segment: int) -> str:
        return _with_segment_index(PKTMON_LOG_FILE_WINDOWS, segment)

    def _pcap_path(self, segment: int) -> str:
        # Keep segment 0 at the plain output path so the common no-roll case
        # downloads exactly as before.
        return (
            self.output_file
            if segment == 0
            else _with_segment_index(self.output_file, segment)
        )

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

    async def _list_interface_names(self) -> set[str]:
        process = await self.connection.create_process(
            ["netsh", "interface", "show", "interface"], quiet=True
        ).execute()
        names: set[str] = set()
        for line in process.get_stdout().splitlines():
            # rows: "<Admin State> <State> <Type> <Interface Name>"; the name
            # can contain spaces, so split off only the first three columns.
            parts = line.split(None, 3)
            if len(parts) == 4 and parts[0] in ("Enabled", "Disabled"):
                names.add(parts[3].strip())
        return names

    def _pktmon_start_args(self, etl_path: str) -> list[str]:
        return [
            "pktmon",
            "start",
            "--capture",
            "--comp",
            "all",
            "--pkt-size",
            "0",
            "--log-mode",
            "circular",
            "--file-size",
            str(PKTMON_MAX_LOG_SIZE_MB),
            "--file-name",
            etl_path,
        ]

    async def _start_session(self, etl_path: str) -> None:
        await self._exec_quiet(self._pktmon_start_args(etl_path), ignore_failure=False)
        self.log_files.append(etl_path)

    async def _reload_pktmon_with_new_adapters(self, new: set[str]) -> None:
        if self._segment + 1 >= PKTMON_MAX_SEGMENTS:
            return
        next_segment = self._segment + 1
        etl_path = self._etl_path(next_segment)
        # Register the .etl and fold the new adapters into the baseline up front:
        # the file gets cleaned up even if the roll is interrupted, and a failing
        # roll won't re-fire on every poll for the same adapter set.
        self.log_files.append(etl_path)
        self._baseline |= new
        # One round-trip stop+start - smallest possible gap (pktmon allows one
        # session per machine, so no overlap). Nested `cmd /c` so a real `&&`
        # survives arg escaping (^&^&) and chains on the VM.
        roll_command = [
            "cmd",
            "/c",
            "pktmon",
            "stop",
            "&&",
            *self._pktmon_start_args(etl_path),
        ]
        try:
            await self._exec_quiet(roll_command, ignore_failure=False)
        except ProcessExecError as e:
            log.warning(
                "[%s] failed to roll pktmon capture: %s",
                self.connection.tag,
                e.stderr or e.stdout,
            )
            return
        self._segment = next_segment
        log.info(
            "[%s] rolled pktmon capture to segment %d for new adapter(s): %s",
            self.connection.tag,
            self._segment,
            ", ".join(sorted(new)),
        )

    async def _poll_for_new_adapters(self) -> None:
        while True:
            await asyncio.sleep(PKTMON_ADAPTER_POLL_INTERVAL_S)
            try:
                current = await self._list_interface_names()
            except Exception as e:  # pylint: disable=broad-exception-caught
                log.debug(
                    "[%s] could not list interfaces while polling: %s",
                    self.connection.tag,
                    e,
                )
                continue
            if not current:
                continue
            if not self._baseline:
                # baseline wasn't captured at start; adopt the first reading
                self._baseline = current
                continue
            new = current - self._baseline
            if new:
                log.info(
                    "[%s] new adapter(s) appeared, rolling pktmon: %s",
                    self.connection.tag,
                    ", ".join(sorted(new)),
                )
                await self._reload_pktmon_with_new_adapters(new)

    async def _convert_segments(self) -> None:
        for segment in range(self._segment + 1):
            etl = self._etl_path(segment)
            pcap = self._pcap_path(segment)
            try:
                await self.connection.create_process(
                    ["pktmon", "etl2pcap", etl, "--out", pcap], quiet=True
                ).execute()
                self.output_files.append(pcap)
            except ProcessExecError as e:
                log.warning(
                    "[%s] failed to convert pktmon segment %d (%s): %s",
                    self.connection.tag,
                    segment,
                    etl,
                    e.stderr or e.stdout,
                )

    @asynccontextmanager
    async def run(self) -> AsyncIterator["PktmonCapture"]:
        start_time = datetime.now()
        # one session per machine: clear any leftover from a crashed run
        await self._exec_quiet(["pktmon", "stop"], ignore_failure=True)
        await self._exec_quiet(["pktmon", "filter", "remove"], ignore_failure=True)
        await self._start_session(self._etl_path(0))
        try:
            self._baseline = await self._list_interface_names()
        except Exception as e:  # pylint: disable=broad-exception-caught
            log.debug(
                "[%s] could not snapshot baseline adapters: %s",
                self.connection.tag,
                e,
            )
        log.info(
            "[%s] pktmon capture ready in %s",
            self.connection.tag,
            datetime.now() - start_time,
        )
        poller = asyncio.create_task(self._poll_for_new_adapters())
        try:
            yield self
        finally:
            poller.cancel()
            try:
                await poller
            except asyncio.CancelledError:
                pass
            except Exception as e:  # pylint: disable=broad-exception-caught
                log.warning(
                    "[%s] pktmon adapter poller errored: %s", self.connection.tag, e
                )
            try:
                await self._exec_quiet(["pktmon", "stop"], ignore_failure=False)
                await self._convert_segments()
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
    if target_os not in [TargetOS.Linux, TargetOS.Mac, TargetOS.Android]:
        raise ValueError(
            f"tcpdump is not supported on {target_os}, use PktmonCapture on Windows"
        )

    if using_sudo:
        command = ["sudo"]
    else:
        command = []
    command += ["tcpdump", "-n"]

    if target_os == TargetOS.Android:
        # Android's tcpdump is torn down abruptly (the container kill script
        # can't reach the guest process behind adb), so write packet-buffered
        # (-U) to avoid losing the last block as a truncated savefile.
        command += ["-U"]

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

    if not include_ssh:
        command += ["--immediate-mode"]
        command += ["port not 22"]

    if expressions:
        command += expressions

    return command


def _bare_ip_ethertype(raw: bytes) -> Optional[int]:
    """If 'raw' is a bare IP packet (no L2 header), return its EtherType.

    pktmon writes every adapter under one Ethernet-typed interface, but the
    tunnel (wintun/wireguard) adapter has no L2 header, so its packets are bare
    IP. We recognise them by matching the IP total length to the captured
    length - a real Ethernet frame's length field is offset by its 14-byte
    header, so this won't misfire on genuine Ethernet frames.
    """
    n = len(raw)
    if n >= 20 and (raw[0] >> 4) == 4 and (raw[0] & 0x0F) >= 5:
        if int.from_bytes(raw[2:4], "big") == n:
            return 0x0800
    if n >= 40 and (raw[0] >> 4) == 6:
        if int.from_bytes(raw[4:6], "big") + 40 == n:
            return 0x86DD
    return None


def _merge_windows_pcaps_sync(segment_paths: list[str], out_path: str) -> None:
    # scapy is only needed on the Windows capture path; import lazily.
    from scapy.all import (  # pylint: disable=import-outside-toplevel
        Ether,
        PcapReader,
        PcapWriter,
        TCP,
    )

    synthetic_l2 = b"\x00" * 12  # zeroed dst+src MAC for wrapped bare-IP packets
    tmp_path = f"{out_path}.merge"
    try:
        writer = PcapWriter(tmp_path, linktype=1)
        try:
            # Segments are temporally disjoint (stop -> start), so capture-order
            # concatenation is time-ordered and duplicate-free.
            for segment_path in segment_paths:
                with PcapReader(segment_path) as reader:
                    for packet in reader:
                        raw = bytes(packet)
                        ethertype = _bare_ip_ethertype(raw)
                        if ethertype is not None:
                            raw = synthetic_l2 + ethertype.to_bytes(2, "big") + raw
                        frame = Ether(raw)
                        tcp = frame.getlayer(TCP)
                        if tcp is not None and 22 in (tcp.sport, tcp.dport):
                            continue  # drop the harness's own SSH (TCP/22) channel
                        frame.time = packet.time
                        writer.write(frame)
        finally:
            writer.close()
        os.replace(tmp_path, out_path)
    except BaseException:
        if os.path.isfile(tmp_path):
            os.remove(tmp_path)
        raise


async def merge_windows_pcaps(segment_paths: list[str], out_path: str) -> bool:
    """Merge pktmon segments into one continuous, normalised pcap, best-effort.

    Concatenates segments in capture order; wraps the tunnel adapter's bare-IP
    packets in Ethernet framing (else Wireshark sees them as malformed) and
    drops the SSH control channel (pktmon can't filter at capture time).
    Returns False on failure, leaving segments untouched for the caller.
    """
    segment_paths = [p for p in segment_paths if os.path.isfile(p)]
    if not segment_paths:
        return False
    try:
        await asyncio.to_thread(_merge_windows_pcaps_sync, segment_paths, out_path)
        return True
    except Exception as e:  # pylint: disable=broad-exception-caught
        log.warning(
            "Failed to merge/normalize Windows pcap segments %s, keeping them: %s",
            segment_paths,
            e,
        )
        return False


def find_unique_path_for_tcpdump(log_dir, guest_name):
    candidate_path = f"{log_dir}/{guest_name}.pcap"
    counter = 1
    # NOTE: counter starting from '1' means that the file will either have no suffix or
    # will have a suffix starting from '2'. This is to make it clear that it's not the
    # first log for that guest/client.
    while os.path.isfile(candidate_path):
        counter += 1
        candidate_path = f"{log_dir}/{guest_name}-{counter}.pcap"
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
) -> Optional["PktmonCapture"]:
    for attempt in range(1, 4):
        try:
            if conn.target_os == TargetOS.Windows:
                capture = PktmonCapture(conn)
                await exit_stack.enter_async_context(capture.run())
                return capture
            await exit_stack.enter_async_context(TcpDump(conn, session=session).run())
            return None
        except Exception as e:  # pylint: disable=broad-exception-caught
            log.warning(
                "Failed to start packet capture on %s (attempt %d/3): %s",
                conn.tag,
                attempt,
                e,
            )
            if attempt >= 3:
                if conn.target_os == TargetOS.Windows:
                    # best-effort on Windows: capture already had to be
                    # disabled once for destabilizing the VMs (LLT-5942)
                    log.error("Continuing without packet capture on %s", conn.tag)
                else:
                    raise e
    return None


async def _download_pktmon_segments(
    conn: Connection, capture: Optional["PktmonCapture"], dest_dir: str
) -> None:
    if capture is None:
        # capture never started (best-effort on Windows) - nothing to fetch
        return
    local_segments: list[str] = []
    for index, segment_file in enumerate(capture.output_files):
        tmp_path = f"{dest_dir}/.{conn.tag.name}-pktmon-seg{index}.pcap.tmp"
        try:
            await conn.download(segment_file, tmp_path)
        except Exception as e:  # pylint: disable=broad-exception-caught
            # one bad segment shouldn't lose the others or skip remote cleanup
            log.warning(
                "[%s] failed to download pktmon segment %s: %s",
                conn.tag,
                segment_file,
                e,
            )
            continue
        if os.path.isfile(tmp_path):
            local_segments.append(tmp_path)
    if local_segments:
        out_path = find_unique_path_for_tcpdump(dest_dir, conn.tag.name)
        if await merge_windows_pcaps(local_segments, out_path):
            for tmp_path in local_segments:
                os.remove(tmp_path)
        else:
            # merge failed: keep the raw segments as separate guest pcaps so
            # the capture isn't lost (unnormalised, SSH not stripped)
            for tmp_path in local_segments:
                os.replace(
                    tmp_path, find_unique_path_for_tcpdump(dest_dir, conn.tag.name)
                )
    leftovers = capture.output_files + capture.log_files
    if leftovers:
        try:
            await conn.create_process(["del", *leftovers], quiet=True).execute()
        except ProcessExecError as e:
            log.debug(
                "[%s] failed to clean up pktmon files: %s",
                conn.tag,
                e.stderr or e.stdout,
            )


@asynccontextmanager
async def make_tcpdump(
    connection_list: list[Connection],
    download: bool = True,
    store_in: Optional[str] = None,
    session: bool = False,
):
    captures: dict[Connection, "PktmonCapture"] = {}
    try:
        async with AsyncExitStack() as exit_stack:
            for conn in connection_list:
                capture = await _start_capture(exit_stack, conn, session)
                if conn.target_os == TargetOS.Windows and capture is not None:
                    captures[conn] = capture
            yield
    finally:
        if download:
            log_dir = get_current_test_log_path()
            os.makedirs(log_dir, exist_ok=True)
            dest_dir = store_in if store_in else log_dir
            for conn in connection_list:
                if conn.target_os == TargetOS.Windows:
                    await _download_pktmon_segments(conn, captures.get(conn), dest_dir)
                    continue
                path = find_unique_path_for_tcpdump(dest_dir, conn.tag.name)
                await conn.download(PCAP_FILE_PATH[conn.target_os], path)
                await conn.create_process(
                    ["rm", "-f", PCAP_FILE_PATH[conn.target_os]], quiet=True
                ).execute()
