#!/usr/bin/python3

import argparse
import sys
import time

# Logged by telio_core::device on startup: "Created libtelio instance {version}, {commit_sha}"
VERSION_LOG_MARKER = b"Created libtelio instance "
NUL = b"\x00"


def read_version_from_log(log_path: str):
    try:
        with open(log_path, "rb") as file:
            for line in file:
                if VERSION_LOG_MARKER in line:
                    return line.split(VERSION_LOG_MARKER, 1)[1].rsplit(b", ", 1)[0]
    except FileNotFoundError:
        pass
    return None


def check_version_in_log(log_path: str, expected_version: str, timeout: float = 0.0):
    # Wait for the log to appear
    deadline = time.monotonic() + timeout
    version = read_version_from_log(log_path)
    while version is None and time.monotonic() < deadline:
        time.sleep(0.5)
        version = read_version_from_log(log_path)

    if version is None:
        raise ValueError(f"No {VERSION_LOG_MARKER.decode()!r} line found in {log_path}")

    # Compare the exact bytes and length
    expected = expected_version.encode()
    if version != expected:
        shown = repr(version[:32]) + ("..." if len(version) > 32 else "")
        raise ValueError(
            f"Expected version {expected!r} (len {len(expected)}), got {shown} "
            f"(len {len(version)}, NUL bytes: {version.count(NUL)})"
        )


def main(args):
    try:
        check_version_in_log(args.log_file, args.expected_version, args.timeout)
        print(f"Version check successful: {args.expected_version}")
        return 0
    except ValueError as e:
        print(f"Error: {e}")
        return 1


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Check that libtelio logs exactly the inserted version"
    )
    parser.add_argument(
        "-n",
        "--expected_version",
        type=str,
        required=True,
        help="Version inserted with insert_libtelio_version.py",
    )
    parser.add_argument(
        "-f", "--log_file", type=str, required=True, help="Log file to check"
    )
    parser.add_argument(
        "-t",
        "--timeout",
        type=float,
        default=10.0,
        help="Seconds to wait for the version line to appear in the log",
    )
    sys.exit(main(parser.parse_args()))
