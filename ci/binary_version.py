import plistlib
import re
import struct
from pathlib import Path
from typing import Optional, Tuple

VERSION_PLACEHOLDER = "VERSION_PLACEHOLDER@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@"

NUMERIC_VERSION_REGEX = re.compile(r"^v?(\d+)\.(\d+)\.(\d+)")

VS_FIXEDFILEINFO_SIGNATURE = struct.pack("<I", 0xFEEF04BD)

MH_MAGIC_64 = 0xFEEDFACF
MACH_HEADER_64_SIZE = 32
LC_ID_DYLIB = 0xD


def parse_numeric_version(version: str) -> Optional[Tuple[int, int, int]]:
    match = NUMERIC_VERSION_REGEX.match(version)
    if not match:
        return None
    major, minor, patch = (int(part) for part in match.groups())
    return major, minor, patch


def patch_pe_version_info(path: str, new_version: str) -> None:
    placeholder = VERSION_PLACEHOLDER.encode("utf-16-le")
    replacement = new_version.encode("utf-16-le")
    if len(replacement) > len(placeholder):
        raise ValueError("New version is longer than the placeholder")

    with open(path, "rb+") as file:
        content = bytearray(file.read())

        if placeholder not in content:
            raise ValueError(f"Version resource placeholder not found in {path}")
        content = content.replace(
            placeholder, replacement.ljust(len(placeholder), b"\x00")
        )

        if content.count(VS_FIXEDFILEINFO_SIGNATURE) != 1:
            raise ValueError(f"Expected exactly one VS_FIXEDFILEINFO in {path}")
        major, minor, patch = parse_numeric_version(new_version) or (0, 0, 0)
        if max(major, minor, patch) > 0xFFFF:
            raise ValueError(f"Version {new_version} does not fit VS_FIXEDFILEINFO")
        version_ms = (major << 16) | minor
        version_ls = patch << 16
        # dwFileVersionMS, dwFileVersionLS, dwProductVersionMS, dwProductVersionLS
        struct.pack_into(
            "<IIII",
            content,
            content.find(VS_FIXEDFILEINFO_SIGNATURE) + 8,
            version_ms,
            version_ls,
            version_ms,
            version_ls,
        )

        file.seek(0)
        file.write(content)


def patch_macho_dylib_version(path: str, new_version: str) -> None:
    numeric = parse_numeric_version(new_version)
    if numeric is None:
        return
    major, minor, patch = numeric
    if major > 0xFFFF or minor > 0xFF or patch > 0xFF:
        raise ValueError(f"Version {new_version} does not fit Mach-O current_version")

    with open(path, "rb+") as file:
        content = file.read()
        magic, _, _, _, ncmds = struct.unpack_from("<IiiII", content, 0)
        if magic != MH_MAGIC_64:
            raise ValueError(f"{path} is not a thin 64-bit Mach-O")

        offset = MACH_HEADER_64_SIZE
        for _ in range(ncmds):
            cmd, cmdsize = struct.unpack_from("<II", content, offset)
            if cmd == LC_ID_DYLIB:
                # dylib_command: cmd, cmdsize, name, timestamp, current_version
                file.seek(offset + 16)
                file.write(struct.pack("<I", (major << 16) | (minor << 8) | patch))
                return
            offset += cmdsize

    raise ValueError(f"LC_ID_DYLIB not found in {path}")


def set_framework_info_plist_versions(root: Path, framework: str, version: str):
    numeric = ".".join(
        str(part) for part in parse_numeric_version(version) or (0, 0, 0)
    )
    plists = {
        plist.resolve()
        for framework_path in root.rglob(f"{framework}.framework")
        for plist in framework_path.rglob("Info.plist")
    }
    if not plists:
        raise ValueError(f"No {framework}.framework Info.plist found in {root}")
    for plist in plists:
        with open(plist, "rb") as file:
            info = plistlib.load(file)
        info["CFBundleShortVersionString"] = numeric
        info["CFBundleVersion"] = version
        with open(plist, "wb") as file:
            plistlib.dump(info, file)
