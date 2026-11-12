import plistlib
import struct
import tempfile
import unittest
from pathlib import Path

from binary_version import (
    LC_ID_DYLIB,
    MH_MAGIC_64,
    VERSION_PLACEHOLDER,
    VS_FIXEDFILEINFO_SIGNATURE,
    patch_macho_dylib_version,
    patch_pe_version_info,
    set_framework_info_plist_versions,
)


def write_temp(content: bytes) -> str:
    with tempfile.NamedTemporaryFile(delete=False) as temp_file:
        temp_file.write(content)
    return temp_file.name


def read(path: str) -> bytes:
    with open(path, "rb") as file:
        return file.read()


def pe_resource() -> bytes:
    fixed_file_info = (
        VS_FIXEDFILEINFO_SIGNATURE + struct.pack("<I", 0x10000) + bytes(44)
    )
    placeholder = VERSION_PLACEHOLDER.encode("utf-16-le")
    return b"head" + fixed_file_info + placeholder + b"mid" + placeholder + b"tail"


def macho_dylib(current_version: int) -> bytes:
    segment = struct.pack("<II", 0x19, 16) + bytes(8)
    id_dylib = struct.pack("<IIIIII", LC_ID_DYLIB, 32, 24, 2, current_version, 0x10000)
    id_dylib += bytes(8)
    header = struct.pack("<IiiIIIII", MH_MAGIC_64, 0, 0, 6, 2, 48, 0, 0)
    return header + segment + id_dylib + b"body"


class TestPatchPeVersionInfo(unittest.TestCase):
    def test_release_tag(self):
        path = write_temp(pe_resource())
        patch_pe_version_info(path, "v8.1.2")

        content = read(path)
        self.assertNotIn(VERSION_PLACEHOLDER.encode("utf-16-le"), content)
        self.assertEqual(content.count("v8.1.2\0".encode("utf-16-le")), 2)
        self.assertEqual(len(content), len(pe_resource()))
        offset = content.find(VS_FIXEDFILEINFO_SIGNATURE) + 8
        self.assertEqual(
            struct.unpack_from("<IIII", content, offset),
            (0x80001, 0x20000, 0x80001, 0x20000),
        )

    def test_non_release_tag_zeroes_numeric_version(self):
        path = write_temp(pe_resource())
        patch_pe_version_info(path, "main-2611021357-fcee6c5")

        content = read(path)
        self.assertIn("main-2611021357-fcee6c5\0".encode("utf-16-le"), content)
        offset = content.find(VS_FIXEDFILEINFO_SIGNATURE) + 8
        self.assertEqual(struct.unpack_from("<IIII", content, offset), (0, 0, 0, 0))

    def test_missing_placeholder(self):
        path = write_temp(VS_FIXEDFILEINFO_SIGNATURE)
        with self.assertRaises(ValueError):
            patch_pe_version_info(path, "v8.1.2")

    def test_missing_fixed_file_info(self):
        path = write_temp(VERSION_PLACEHOLDER.encode("utf-16-le"))
        with self.assertRaises(ValueError):
            patch_pe_version_info(path, "v8.1.2")


class TestPatchMachODylibVersion(unittest.TestCase):
    def current_version(self, path: str) -> int:
        return struct.unpack_from("<I", read(path), 32 + 16 + 16)[0]

    def test_release_tag(self):
        path = write_temp(macho_dylib(0))
        patch_macho_dylib_version(path, "v8.1.2-rc3")
        self.assertEqual(self.current_version(path), 0x80102)

    def test_non_release_tag_is_left_untouched(self):
        path = write_temp(macho_dylib(0))
        patch_macho_dylib_version(path, "nightly-2611021357-fcee6c5")
        self.assertEqual(read(path), macho_dylib(0))

    def test_version_too_large(self):
        path = write_temp(macho_dylib(0))
        with self.assertRaises(ValueError):
            patch_macho_dylib_version(path, "v8.256.0")

    def test_not_macho(self):
        path = write_temp(bytes(64))
        with self.assertRaises(ValueError):
            patch_macho_dylib_version(path, "v8.1.2")


class TestSetFrameworkInfoPlistVersions(unittest.TestCase):
    def make_framework(self, root: Path, relative: str) -> Path:
        plist = root / relative
        plist.parent.mkdir(parents=True)
        with open(plist, "wb") as file:
            plistlib.dump({"CFBundleVersion": "1.0.0"}, file)
        return plist

    def load(self, plist: Path) -> dict:
        with open(plist, "rb") as file:
            return plistlib.load(file)

    def test_release_and_untagged_versions(self):
        for version, short in [
            ("v8.1.2", "8.1.2"),
            ("main-2611121019-abcdef1", "0.0.0"),
        ]:
            with tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                plists = [
                    self.make_framework(
                        root, "ios/release/telioFFI.framework/Info.plist"
                    ),
                    self.make_framework(
                        root,
                        "x.xcframework/macos/telioFFI.framework/Versions/A/Resources/Info.plist",
                    ),
                ]
                set_framework_info_plist_versions(root, "telioFFI", version)
                for plist in plists:
                    info = self.load(plist)
                    self.assertEqual(info["CFBundleShortVersionString"], short)
                    self.assertEqual(info["CFBundleVersion"], version)

    def test_no_framework(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(ValueError):
                set_framework_info_plist_versions(Path(tmp), "telioFFI", "v8.1.2")


if __name__ == "__main__":
    unittest.main()
