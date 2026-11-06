import os
import tempfile
import unittest

from check_libtelio_version import check_version_in_log

# Prefix to make logs look real
PREFIX = "2026-11-06T11:31:41.920808Z  INFO telio_core::device: 565: "


class TestCheckVersionInLog(unittest.TestCase):
    def write_log(self, content: bytes) -> str:
        with tempfile.NamedTemporaryFile(mode="wb", delete=False) as temp_file:
            temp_file.write(content)
        self.addCleanup(os.remove, temp_file.name)
        return temp_file.name

    def test_correct_version(self):
        log = self.write_log(
            f"{PREFIX}Created libtelio instance TEST_VERSION, dev\n".encode()
        )
        check_version_in_log(log, "TEST_VERSION")

    def test_version_line_not_first(self):
        log = self.write_log(
            f"{PREFIX}something else\n{PREFIX}Created libtelio instance TEST_VERSION,"
            " dev\n".encode()
        )
        check_version_in_log(log, "TEST_VERSION")

    def test_version_with_nul_padding(self):
        log = self.write_log(
            PREFIX.encode()
            + b"Created libtelio instance TEST_VERSION"
            + b"\x00" * 116
            + b", dev\n"
        )
        with self.assertRaises(ValueError):
            check_version_in_log(log, "TEST_VERSION")

    def test_version_with_suffix(self):
        log = self.write_log(
            f"{PREFIX}Created libtelio instance TEST_VERSION-extra, dev\n".encode()
        )
        with self.assertRaises(ValueError):
            check_version_in_log(log, "TEST_VERSION")

    def test_version_not_replaced(self):
        log = self.write_log(
            f"{PREFIX}Created libtelio instance VERSION_PLACEHOLDER@@@@, dev\n".encode()
        )
        with self.assertRaises(ValueError):
            check_version_in_log(log, "TEST_VERSION")

    def test_no_version_line(self):
        log = self.write_log(f"{PREFIX}something else\n".encode())
        with self.assertRaises(ValueError):
            check_version_in_log(log, "TEST_VERSION")

    def test_missing_log_file(self):
        with self.assertRaises(ValueError):
            check_version_in_log("/nonexistent/tcli.log", "TEST_VERSION")


if __name__ == "__main__":
    unittest.main()
