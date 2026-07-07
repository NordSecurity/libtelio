import asyncio
import os
import pytest
from utils.connection import Connection, ConnectionTag, TargetOS
from utils.connection_util import new_connection_raw
from utils.logger import log
from utils.process import ProcessExecError
from utils.python import get_python_binary

# Reproduces the production abort caused by a bad OPENSSL_ia32cap value.
#
# libtelio (with the default `enable_ens` feature) statically links aws-lc-sys.
# aws-lc registers `OPENSSL_cpuid_setup` as a load-time static initializer:
#   * Linux/macOS: __attribute__((constructor))       (crypto/crypto.c:56)
#   * Windows:     a .CRT$XCU entry run by the MSVC CRT `_initterm` at DLL load
#                                                      (crypto/crypto.c:50-54)
# That initializer calls `handle_cpu_env` (crypto/fipsmodule/cpucap/cpu_intel.c),
# which reads OPENSSL_ia32cap and *aborts the whole process* if the value asks
# for a CPU capability bit the running CPU does not have:
#
#     if (!invert && (intelcap0 || intelcap1)) {
#       if ((~(1u << 30 | intelcap0) & reqcap0) || (~intelcap1 & reqcap1)) {
#         fprintf(stderr, "Fatal Error: HW capability found: ... requested: ...");
#         abort();
#       }
#     }
#
# Because it is a load-time initializer of the linked-in aws-lc, the abort fires
# the moment libtelio is loaded (`import telio_bindings` -> dlopen/LoadLibrary of
# the lib), before any Rust/libtelio code runs. This matches the reported crash
# stack: handle_cpu_env <- OPENSSL_cpuid_setup <- do_library_init <- _initterm.
# handle_cpu_env is `static`, so with public-only symbols it shows up as the
# nearest exported symbol + offset in a dump (e.g. `...!get_entropy+0x...`).

# Value with no '~'/'|' prefix requesting all capability bits -> guaranteed to
# request a bit the CPU lacks -> aws-lc abort() on any real x86_64 CPU.
BAD_IA32CAP = "0xffffffffffffffff"

# stderr signature printed by aws-lc's handle_cpu_env right before abort().
AWS_LC_ABORT_MARKER = "Fatal Error: HW capability"


def _uniffi_dir(connection: Connection) -> str:
    if connection.target_os == TargetOS.Linux:
        return "/libtelio/nat-lab/tests/uniffi"
    if connection.target_os == TargetOS.Windows:
        return "C:/workspace/uniffi"
    if connection.target_os == TargetOS.Mac:
        return "/var/root/workspace/uniffi"
    assert False, f"unsupported target_os {connection.target_os}"


async def _run_import(connection: Connection, ia32cap):
    """Load the libtelio binding in a *fresh* child process, optionally with
    OPENSSL_ia32cap set in that process' environment *before* it starts (exactly
    as it was in production). Importing the binding dlopen()s/LoadLibrary()s
    libtelio, which is where the aws-lc load-time initializer runs.

    The env var must be inherited at launch, not injected at runtime: aws-lc reads
    it with getenv() during the load-time initializer, and on Windows the
    mingw-built telio.dll uses msvcrt while python uses UCRT, so a runtime
    os.environ/putenv from python would be invisible to the DLL's getenv."""
    uniffi_dir = _uniffi_dir(connection)

    if connection.target_os == TargetOS.Windows:
        # PowerShell sets the env var for the child `python` it launches; running
        # from the uniffi dir puts both telio_bindings.py and telio.dll on the
        # default search paths. `exit $LASTEXITCODE` propagates the crash code.
        prefix = f"$env:OPENSSL_ia32cap='{ia32cap}'; " if ia32cap is not None else ""
        script = (
            f"{prefix}cd '{uniffi_dir}'; "
            "python -c 'import telio_bindings'; exit $LASTEXITCODE"
        )
        cmd = ["powershell", "-Command", script]
    else:
        lines = ["import os, sys", f"sys.path.insert(0, r'{uniffi_dir}')"]
        if ia32cap is not None:
            lines.append(f"os.environ['OPENSSL_ia32cap'] = r'{ia32cap}'")
        lines.append("import telio_bindings")
        cmd = [get_python_binary(connection), "-c", "; ".join(lines)]

    return await connection.create_process(cmd, quiet=True).execute()


async def _skip_if_not_x86_64(connection: Connection) -> None:
    if connection.target_os == TargetOS.Windows:
        cmd = ["cmd", "/c", "echo %PROCESSOR_ARCHITECTURE%"]
        expected = "AMD64"
    else:
        cmd = ["uname", "-m"]
        expected = "x86_64"
    arch = (
        (await connection.create_process(cmd, quiet=True).execute()).get_stdout().strip()
    )
    if arch != expected:
        pytest.skip(
            f"OPENSSL_ia32cap abort is x86_64-specific (aws-lc cpu_intel.c); arch is {arch}"
        )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "connection_tag",
    [
        pytest.param(ConnectionTag.DOCKER_CONE_CLIENT_1),
        pytest.param(ConnectionTag.VM_WINDOWS_1, marks=pytest.mark.windows),
    ],
)
async def test_openssl_ia32cap_bad_value_aborts_libtelio_startup(
    connection_tag: ConnectionTag,
) -> None:
    async with new_connection_raw(connection_tag) as connection:
        await _skip_if_not_x86_64(connection)

        # Control: the binding loads cleanly when OPENSSL_ia32cap is not set.
        await _run_import(connection, ia32cap=None)

        # Reproduction: a bad OPENSSL_ia32cap aborts aws-lc while the lib is
        # loaded, killing the process before any libtelio code runs.
        with pytest.raises(ProcessExecError) as exc_info:
            await _run_import(connection, ia32cap=BAD_IA32CAP)

        err = exc_info.value
        assert AWS_LC_ABORT_MARKER in err.stderr, (
            "expected aws-lc capability abort message on stderr, got:\n"
            f"returncode={err.returncode}\nstderr:\n{err.stderr}"
        )
        assert err.returncode != 0, "expected non-zero exit from the aborted process"


# --- Windows crash-dump capture ------------------------------------------------
#
# On Windows the abort() is a native C fault raised from the CRT `_initterm` at
# DLL load, so nothing self-symbolizes. To get a post-mortem stack comparable to
# the customer's report we enable Windows Error Reporting (WER) LocalDumps, let
# the aborting process fault, then pull the resulting .dmp back to the host.

WINDOWS_DUMP_DIR = "C:/workspace/crashdumps"
LOCAL_DUMP_DIR = "crashdumps"
WER_LOCALDUMPS_KEY = (
    r"HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\LocalDumps"
)


async def _configure_wer_localdumps(connection: Connection) -> None:
    """Enable full-memory WER LocalDumps into WINDOWS_DUMP_DIR (needs admin)."""
    dump_dir = WINDOWS_DUMP_DIR.replace("/", "\\")
    steps = [
        ["cmd", "/c", f"if not exist {dump_dir} mkdir {dump_dir}"],
        # DumpType 2 == full dump (MiniDumpWithFullMemory).
        ["reg", "add", WER_LOCALDUMPS_KEY, "/v", "DumpFolder",
         "/t", "REG_EXPAND_SZ", "/d", dump_dir, "/f"],
        ["reg", "add", WER_LOCALDUMPS_KEY, "/v", "DumpType",
         "/t", "REG_DWORD", "/d", "2", "/f"],
        ["reg", "add", WER_LOCALDUMPS_KEY, "/v", "DumpCount",
         "/t", "REG_DWORD", "/d", "10", "/f"],
        ["reg", "add", r"HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting",
         "/v", "Disabled", "/t", "REG_DWORD", "/d", "0", "/f"],
    ]
    try:
        for step in steps:
            await connection.create_process(step, quiet=True).execute()
    except ProcessExecError as e:
        pytest.skip(
            "cannot configure WER LocalDumps (needs an elevated SSH session on the"
            f" Windows VM): {e.stdout} {e.stderr}"
        )


async def _list_dumps(connection: Connection) -> set:
    dump_dir = WINDOWS_DUMP_DIR.replace("/", "\\")
    try:
        out = (
            await connection.create_process(
                ["cmd", "/c", f"dir /b {dump_dir}\\*.dmp"], quiet=True
            ).execute()
        ).get_stdout()
    except ProcessExecError:
        return set()
    return {
        line.strip()
        for line in out.splitlines()
        if line.strip().lower().endswith(".dmp")
    }


@pytest.mark.asyncio
@pytest.mark.windows
async def test_openssl_ia32cap_windows_crashdump() -> None:
    async with new_connection_raw(ConnectionTag.VM_WINDOWS_1) as connection:
        await _skip_if_not_x86_64(connection)
        await _configure_wer_localdumps(connection)
        before = await _list_dumps(connection)

        # Trigger the aws-lc abort at libtelio load time.
        with pytest.raises(ProcessExecError) as exc_info:
            await _run_import(connection, ia32cap=BAD_IA32CAP)
        assert AWS_LC_ABORT_MARKER in exc_info.value.stderr, (
            "expected aws-lc capability abort message on stderr, got:\n"
            f"returncode={exc_info.value.returncode}\nstderr:\n{exc_info.value.stderr}"
        )

        # WerFault writes the dump asynchronously after the process dies.
        new_dumps: list = []
        for _ in range(30):
            new_dumps = sorted(await _list_dumps(connection) - before)
            if new_dumps:
                break
            await asyncio.sleep(1)
        assert new_dumps, (
            f"no WER crash dump appeared in {WINDOWS_DUMP_DIR}; abort() may not have"
            " triggered WER on this VM (consider procdump/cdb as a fallback)"
        )

        os.makedirs(LOCAL_DUMP_DIR, exist_ok=True)
        for name in new_dumps:
            local_path = os.path.join(LOCAL_DUMP_DIR, name)
            await connection.download(f"{WINDOWS_DUMP_DIR}/{name}", local_path)
            log.info("Downloaded crash dump: %s", local_path)
