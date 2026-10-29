import asyncio
import json
import os
import sys
from dataclasses import dataclass
from pathlib import Path
from tests.config import get_root_path
from tests.utils.connection import TargetOS
from typing import List, Tuple

SYMBOLIZE_SCRIPT = "ci/symbolize.py"
LINUX_LIBRARY = "nat-lab/tests/uniffi/libtelio.so"
MAC_LIBRARY = "dist/darwin/macos/{profile}/x86_64/libtelio.dylib"
WINDOWS_LIBRARY = "dist/windows/{profile}/x86_64/telio.dll"
ELF_DEBUG_SUFFIX = ".debug"
DSYM_SUFFIX = ".dSYM"
PDB_SUFFIX = ".pdb"


@dataclass
class ResolvedFunction:
    function: str
    file: str
    line: int


@dataclass
class ResolvedBacktrace:
    module_id: str
    functions: List[ResolvedFunction]


def libtelio_debug_files(target_os: TargetOS) -> Tuple[Path, Path]:
    profile = os.getenv("TELIO_BIN_PROFILE")
    if target_os == TargetOS.Linux:
        library = Path(get_root_path(LINUX_LIBRARY))
        debug = library.with_name(library.name + ELF_DEBUG_SUFFIX)
        if debug.exists():
            return library, debug
        return library, library
    if target_os == TargetOS.Mac:
        library = Path(get_root_path(MAC_LIBRARY.format(profile=profile)))
        return library, library.with_name(library.name + DSYM_SUFFIX)
    if target_os == TargetOS.Windows:
        library = Path(get_root_path(WINDOWS_LIBRARY.format(profile=profile)))
        return library, library.with_suffix(PDB_SUFFIX)
    raise ValueError(f"no libtelio debug files for {target_os}")


async def resolve_return_addresses(
    library: Path, debug: Path, addresses: List[int]
) -> ResolvedBacktrace:
    process = await asyncio.create_subprocess_exec(
        sys.executable,
        get_root_path(SYMBOLIZE_SCRIPT),
        "--json",
        "--return-address",
        str(library),
        str(debug),
        *map(hex, addresses),
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    stdout, stderr = await process.communicate()
    if process.returncode != 0:
        raise RuntimeError(f"{SYMBOLIZE_SCRIPT} failed: {stderr.decode().strip()}")
    result = json.loads(stdout)
    return ResolvedBacktrace(
        result["module_id"],
        [
            ResolvedFunction(frame["function"], frame["file"], frame["line"])
            for address in result["addresses"]
            for frame in address["frames"]
        ],
    )
