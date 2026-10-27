import re
import subprocess
from pathlib import Path

ELF_BUILD_ID = re.compile(r"Build ID:\s*([0-9a-f]+)")
ELF_DEBUG_INFO = re.compile(r"\]\s+\.debug_info\s+(\S+)\s+\S+\s+\S+\s+([0-9a-f]+)")
ELF_SECTION_WITH_DATA = "PROGBITS"
MACHO_UUID = re.compile(r"UUID:\s*([0-9A-F-]+)\s+\((\S+)\)")
DSYM_DEBUG_INFO = re.compile(r"^__debug_info\s+(\d+)", re.MULTILINE)
PE_CODEVIEW = re.compile(
    r"Format:\s*RSDS,\s*\{([0-9A-Fa-f-]+)\},\s*(\d+),\s*(.+?)\s*$", re.MULTILINE
)


class DebugIdError(Exception):
    pass


def check_elf(readelf: str, lib: Path, debug: Path) -> None:
    lib_id = _elf_build_id(readelf, lib)
    debug_id = _elf_build_id(readelf, debug)
    if lib_id != debug_id:
        raise DebugIdError(
            f"{lib} has build ID {lib_id}, but {debug} has build ID {debug_id}"
        )
    sections = _run([readelf, "-S", "-W", str(debug)])
    match = ELF_DEBUG_INFO.search(sections)
    if match is None or match[1] != ELF_SECTION_WITH_DATA or int(match[2], 16) == 0:
        raise DebugIdError(f"{debug} has no .debug_info")
    print(f"{lib.name} and {debug.name} have build ID {lib_id}")


def check_macho(dwarfdump: str, lib: Path, dsym: Path) -> None:
    lib_uuids = _macho_uuids(dwarfdump, lib)
    dsym_uuids = _macho_uuids(dwarfdump, dsym)
    if lib_uuids != dsym_uuids:
        raise DebugIdError(
            f"{lib} has UUIDs {lib_uuids}, but {dsym} has UUIDs {dsym_uuids}"
        )
    sizes = _run([dwarfdump, "--show-section-sizes", str(dsym)])
    match = DSYM_DEBUG_INFO.search(sizes)
    if match is None or int(match[1]) == 0:
        raise DebugIdError(f"{dsym} has no __debug_info")
    print(f"{lib.name} and {dsym.name} have UUIDs {lib_uuids}")


def check_pe(dumpbin: str, dll: Path, pdb: Path) -> None:
    headers = _run([dumpbin, "/headers", str(dll)])
    match = PE_CODEVIEW.search(headers)
    if match is None:
        raise DebugIdError(f"{dll} has no CodeView debug record")
    guid, age, pdb_name = match[1], match[2], Path(match[3]).name
    if pdb_name.lower() != pdb.name.lower():
        raise DebugIdError(f"{dll} points to {pdb_name}, expected {pdb.name}")
    if not pdb.is_file() or pdb.stat().st_size == 0:
        raise DebugIdError(f"{pdb} is missing or empty")
    # NOTE: There is no built-in command line tool on windows or in msvc that
    # can read guid and age from the pdb file.
    print(f"{dll.name} points to {pdb.name} with GUID {guid} and age {age}")


def _elf_build_id(readelf: str, path: Path) -> str:
    match = ELF_BUILD_ID.search(_run([readelf, "-n", str(path)]))
    if match is None:
        raise DebugIdError(f"{path} has no build ID")
    return match[1]


def _macho_uuids(dwarfdump: str, path: Path) -> dict[str, str]:
    output = _run([dwarfdump, "--uuid", str(path)])
    uuids = {arch: uuid for uuid, arch in MACHO_UUID.findall(output)}
    if not uuids:
        raise DebugIdError(f"{path} has no UUID")
    return uuids


def _run(command: list[str]) -> str:
    result = subprocess.run(
        command, check=False, capture_output=True, text=True, errors="replace"
    )
    if result.returncode != 0:
        raise DebugIdError(f"{' '.join(command)} failed: {result.stderr.strip()}")
    return result.stdout
