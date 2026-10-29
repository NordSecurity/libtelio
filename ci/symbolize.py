#!/usr/bin/env python3
"""Print the function, file and line of addresses in a libtelio library, using its debug file."""

import argparse
import json
import re
import sys
from enum import Enum
from pathlib import Path
from typing import NamedTuple, Optional

import debug_ids

LLVM_SYMBOLIZER = "llvm-symbolizer"
LLVM_READELF = "llvm-readelf"
LLVM_DWARFDUMP = "llvm-dwarfdump"
LLVM_READOBJ = "llvm-readobj"
LLVM_PDBUTIL = "llvm-pdbutil"

ELF_MAGIC = b"\x7fELF"
PE_MAGIC = b"MZ"
MACHO_MAGICS = {
    bytes.fromhex(magic)
    for magic in (
        "feedface",
        "cefaedfe",
        "feedfacf",
        "cffaedfe",
        "cafebabe",
        "bebafeca",
    )
}
MAGIC_SIZE = 4
DSYM_DWARF_DIR = Path("Contents", "Resources", "DWARF")

PE_IMAGE_BASE = re.compile(r"ImageBase:\s*(0x[0-9A-Fa-f]+)")
PE_PDB_GUID = re.compile(r"PDBGUID:\s*\{([0-9A-Fa-f-]+)\}")
PE_PDB_AGE = re.compile(r"PDBAge:\s*(\d+)")
PDB_GUID = re.compile(r"^\s*GUID:\s*\{([0-9A-Fa-f-]+)\}", re.MULTILINE)
PDB_AGE = re.compile(r"^\s*Age:\s*(\d+)", re.MULTILINE)

RETURN_ADDRESS_ADJUSTMENT = 1
UNKNOWN = "??"


class Format(Enum):
    ELF = "ELF"
    MACHO = "Mach-O"
    PE = "PE"


class AddressKind(Enum):
    INSTRUCTION = "instruction"
    RETURN = "return"


class Lookup(NamedTuple):
    symbolizer_args: list[str]
    address_offset: int


class Llvm:
    def __init__(self, bin_dir: Optional[Path]) -> None:
        self._bin_dir = bin_dir

    def tool(self, name: str) -> str:
        if self._bin_dir is None:
            return name
        return str(self._bin_dir / name)


def detect_format(lib: Path) -> Format:
    with lib.open("rb") as file:
        magic = file.read(MAGIC_SIZE)
    if magic == ELF_MAGIC:
        return Format.ELF
    if magic in MACHO_MAGICS:
        return Format.MACHO
    if magic.startswith(PE_MAGIC):
        return Format.PE
    raise debug_ids.DebugIdError(f"{lib} is not an ELF, Mach-O or PE library")


def prepare_elf(llvm: Llvm, lib: Path, debug: Path) -> Lookup:
    debug_ids.check_elf(llvm.tool(LLVM_READELF), lib, debug)
    return Lookup([f"--obj={debug}"], 0)


def prepare_macho(llvm: Llvm, lib: Path, debug: Path) -> Lookup:
    dwarf = dsym_dwarf_file(debug)
    dwarfdump = llvm.tool(LLVM_DWARFDUMP)
    lib_uuids = debug_ids.macho_uuids(dwarfdump, lib)
    dsym_uuids = debug_ids.macho_uuids(dwarfdump, dwarf)
    if len(dsym_uuids) != 1:
        raise debug_ids.DebugIdError(
            f"{dwarf} has architectures {sorted(dsym_uuids)}, pass a dSYM of one architecture"
        )
    [(arch, uuid)] = dsym_uuids.items()
    if lib_uuids.get(arch) != uuid:
        raise debug_ids.DebugIdError(
            f"{lib} has UUIDs {lib_uuids}, but {dwarf} has UUID {uuid} ({arch})"
        )
    print(f"{lib.name} and {debug.name} have UUID {uuid} ({arch})")
    return Lookup([f"--obj={dwarf}", f"--default-arch={arch}"], 0)


def dsym_dwarf_file(debug: Path) -> Path:
    if debug.is_file():
        return debug
    files = list((debug / DSYM_DWARF_DIR).glob("*"))
    if len(files) != 1:
        raise debug_ids.DebugIdError(f"{debug} is not a dSYM bundle of one library")
    return files[0]


def prepare_pe(llvm: Llvm, lib: Path, debug: Path) -> Lookup:
    headers = debug_ids.run(
        [llvm.tool(LLVM_READOBJ), "--file-headers", "--coff-debug-directory", str(lib)]
    )
    summary = debug_ids.run([llvm.tool(LLVM_PDBUTIL), "dump", "--summary", str(debug)])
    lib_guid = search(PE_PDB_GUID, headers, lib, "PDB GUID").upper()
    lib_age = search(PE_PDB_AGE, headers, lib, "PDB age")
    pdb_guid = search(PDB_GUID, summary, debug, "GUID").upper()
    pdb_age = search(PDB_AGE, summary, debug, "age")
    if (lib_guid, lib_age) != (pdb_guid, pdb_age):
        raise debug_ids.DebugIdError(
            f"{lib} expects GUID {lib_guid} and age {lib_age}, "
            f"but {debug} has GUID {pdb_guid} and age {pdb_age}"
        )
    print(f"{lib.name} and {debug.name} have GUID {lib_guid} and age {lib_age}")
    image_base = int(search(PE_IMAGE_BASE, headers, lib, "ImageBase"), 16)
    return Lookup([f"--obj={lib}", f"--pdb={debug}"], image_base)


def search(pattern: re.Pattern, text: str, path: Path, what: str) -> str:
    match = pattern.search(text)
    if match is None:
        raise debug_ids.DebugIdError(f"{path} has no {what}")
    return match[1]


PREPARE = {
    Format.ELF: prepare_elf,
    Format.MACHO: prepare_macho,
    Format.PE: prepare_pe,
}


def symbolize(
    llvm: Llvm, lookup: Lookup, addresses: list[int], kind: AddressKind
) -> None:
    adjustment = RETURN_ADDRESS_ADJUSTMENT if kind == AddressKind.RETURN else 0
    queries = [
        hex(address - adjustment + lookup.address_offset) for address in addresses
    ]
    output = debug_ids.run(
        [
            llvm.tool(LLVM_SYMBOLIZER),
            "--output-style=JSON",
            *lookup.symbolizer_args,
            *queries,
        ]
    )
    for address, result in zip(addresses, json.loads(output)):
        print(hex(address))
        for frame in result["Symbol"]:
            print(f"  {format_frame(frame)}")


def format_frame(frame: dict) -> str:
    function = frame["FunctionName"] or UNKNOWN
    if not frame["FileName"]:
        return function
    return f"{function} at {frame['FileName']}:{frame['Line']}:{frame['Column']}"


def parse_address(text: str) -> int:
    return int(text, 0)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "library", type=Path, help="libtelio.so, libtelio.dylib or telio.dll"
    )
    parser.add_argument(
        "debug",
        type=Path,
        help="libtelio.so.debug, libtelio.dylib.dSYM (one architecture) or telio.pdb",
    )
    parser.add_argument(
        "addresses",
        nargs="+",
        type=parse_address,
        help="addresses relative to the start of the library, for example 0x5786dc",
    )
    parser.add_argument(
        "--return-address",
        action="store_true",
        help="the addresses come from a backtrace and point after a call, "
        "print the line of the call",
    )
    parser.add_argument(
        "--llvm-bin",
        type=Path,
        help="directory with the LLVM tools, when they are not on PATH",
    )
    args = parser.parse_args()

    for path in (args.library, args.debug):
        if not path.exists():
            sys.exit(f"error: {path} does not exist")

    llvm = Llvm(args.llvm_bin)
    kind = AddressKind.RETURN if args.return_address else AddressKind.INSTRUCTION
    try:
        lookup = PREPARE[detect_format(args.library)](llvm, args.library, args.debug)
        symbolize(llvm, lookup, args.addresses, kind)
    except debug_ids.DebugIdError as error:
        sys.exit(f"error: {error}")
    except FileNotFoundError as error:
        sys.exit(f"error: {error.filename} not found, install LLVM or pass --llvm-bin")


if __name__ == "__main__":
    main()
