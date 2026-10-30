#!/usr/bin/env python3
"""Print the function, file and line of addresses in a libtelio library, using its debug file."""

import argparse
import json
import re
import sys
import uuid
from enum import Enum
from pathlib import Path, PureWindowsPath
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
PE_PDB_GUID = re.compile(
    r"PDBGUID:\s*(?:\{(?P<text>[0-9A-Fa-f-]+)\}|\((?P<bytes>[0-9A-Fa-f ]+)\))"
)
PE_PDB_AGE = re.compile(r"PDBAge:\s*(\d+)")
PE_PDB_NAME = re.compile(r"PDBFileName:\s*(.+?)\s*$", re.MULTILINE)
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


class Output(Enum):
    TEXT = "text"
    JSON = "json"


class Lookup(NamedTuple):
    symbolizer_args: list[str]
    address_offset: int
    module_id: str


class Frame(NamedTuple):
    function: str
    file: str
    line: int
    column: int


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
    build_id = debug_ids.matching_elf_build_id(llvm.tool(LLVM_READELF), lib, debug)
    return Lookup([f"--obj={debug}"], 0, build_id)


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
    return Lookup([f"--obj={dwarf}", f"--default-arch={arch}"], 0, uuid.lower())


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
    lib_guid = pe_pdb_guid(headers, lib)
    lib_age = int(search(PE_PDB_AGE, headers, lib, "PDB age"))
    pdb_guid = uuid.UUID(search(PDB_GUID, summary, debug, "GUID"))
    pdb_age = int(search(PDB_AGE, summary, debug, "age"))
    if (lib_guid, lib_age) != (pdb_guid, pdb_age):
        raise debug_ids.DebugIdError(
            f"{lib} expects GUID {lib_guid} and age {lib_age}, "
            f"but {debug} has GUID {pdb_guid} and age {pdb_age}"
        )
    pdb_name = PureWindowsPath(search(PE_PDB_NAME, headers, lib, "PDB name")).name
    expected_pdb = lib.parent / pdb_name
    if debug.resolve() != expected_pdb.resolve():
        raise debug_ids.DebugIdError(
            f"{LLVM_SYMBOLIZER} reads the PDB next to the DLL, put {debug} at {expected_pdb}"
        )
    image_base = int(search(PE_IMAGE_BASE, headers, lib, "ImageBase"), 16)
    module_id = f"{lib_guid.hex.upper()}{lib_age:X}"
    return Lookup([f"--obj={lib}"], image_base, module_id)


def pe_pdb_guid(headers: str, lib: Path) -> uuid.UUID:
    match = PE_PDB_GUID.search(headers)
    if match is None:
        raise debug_ids.DebugIdError(f"{lib} has no PDB GUID")
    if match["text"] is not None:
        return uuid.UUID(match["text"])
    return uuid.UUID(bytes_le=bytes.fromhex(match["bytes"]))


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


def resolve(
    llvm: Llvm, lookup: Lookup, addresses: list[int], kind: AddressKind
) -> list[list[Frame]]:
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
    return [
        [
            Frame(
                frame["FunctionName"], frame["FileName"], frame["Line"], frame["Column"]
            )
            for frame in result["Symbol"]
        ]
        for result in json.loads(output)
    ]


def print_text(
    lib: Path,
    debug: Path,
    lookup: Lookup,
    addresses: list[int],
    resolved: list[list[Frame]],
) -> None:
    print(f"{lib.name} and {debug.name} have ID {lookup.module_id}")
    for address, frames in zip(addresses, resolved):
        print(hex(address))
        for frame in frames:
            print(f"  {format_frame(frame)}")


def format_frame(frame: Frame) -> str:
    function = frame.function or UNKNOWN
    if not frame.file:
        return function
    return f"{function} at {frame.file}:{frame.line}:{frame.column}"


def print_json(
    lookup: Lookup, addresses: list[int], resolved: list[list[Frame]]
) -> None:
    print(
        json.dumps(
            {
                "module_id": lookup.module_id,
                "addresses": [
                    {
                        "address": hex(address),
                        "frames": [frame._asdict() for frame in frames],
                    }
                    for address, frames in zip(addresses, resolved)
                ],
            }
        )
    )


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
    parser.add_argument(
        "--json",
        action="store_true",
        help="print the library ID and the functions of each address as JSON",
    )
    args = parser.parse_args()

    for path in (args.library, args.debug):
        if not path.exists():
            sys.exit(f"error: {path} does not exist")

    llvm = Llvm(args.llvm_bin)
    kind = AddressKind.RETURN if args.return_address else AddressKind.INSTRUCTION
    output = Output.JSON if args.json else Output.TEXT
    try:
        lookup = PREPARE[detect_format(args.library)](llvm, args.library, args.debug)
        resolved = resolve(llvm, lookup, args.addresses, kind)
    except debug_ids.DebugIdError as error:
        sys.exit(f"error: {error}")
    except FileNotFoundError as error:
        sys.exit(f"error: {error.filename} not found, install LLVM or pass --llvm-bin")

    if output == Output.JSON:
        print_json(lookup, args.addresses, resolved)
        return
    print_text(args.library, args.debug, lookup, args.addresses, resolved)


if __name__ == "__main__":
    main()
