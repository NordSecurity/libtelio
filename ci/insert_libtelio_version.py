#!/usr/bin/python3

import argparse
import os
import replace_string
import sys
from binary_version import (
    VERSION_PLACEHOLDER,
    patch_macho_dylib_version,
    patch_pe_version_info,
)
from build_libtelio import LIBTELIO_CONFIG


def insert_version(binary: str, new_version: str):
    replace_string.replace_string_in_file(binary, VERSION_PLACEHOLDER, new_version)
    if binary.endswith(".dll"):
        patch_pe_version_info(binary, new_version)
    elif binary.endswith(".dylib"):
        patch_macho_dylib_version(binary, new_version)


def insert_version_to_libtelio_binaries_in_dir(new_version: str, path: str):
    if not os.path.exists(path):
        raise ValueError("Directory does not exist")

    is_valid_package = False
    for target_os, os_config in LIBTELIO_CONFIG.items():
        packages = [
            list(package.values())[0]
            for package in list(os_config.get("packages", {}).values())
        ]

        if not os.path.isdir(path):
            if target_os in path and any(
                package for package in packages if package in path
            ):
                print(f"{target_os}:{path}")
                is_valid_package = True
                insert_version(path, new_version)
        else:
            for dirname, subdirnames, filenames in os.walk(path):
                if "dSYM" in dirname:
                    subdirnames[:] = []
                    continue
                for filename in filenames:
                    full_path = os.path.join(dirname, filename)
                    if target_os in full_path and filename in packages:
                        binary = os.path.join(dirname, filename)
                        print(f"{target_os}:{binary}")
                        is_valid_package = True
                        insert_version(binary, new_version)
    if not is_valid_package:
        raise ValueError(f"Path {path} doesn't contain any libtelio packages")


def main(args):
    try:
        insert_version_to_libtelio_binaries_in_dir(args.new_version, args.path)
        print("Insert successful!")
        return 0
    except ValueError as e:
        print(f"Error: {e}")
        return 1


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-n",
        "--new_version",
        type=str,
        required=True,
        help="New libtelio version to insert",
    )
    parser.add_argument(
        "-p",
        "--path",
        type=str,
        required=True,
        help="Path where to search for libtelio binaries",
    )
    sys.exit(main(parser.parse_args()))
