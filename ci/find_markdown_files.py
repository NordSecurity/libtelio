#!/usr/bin/env python3
import os
import re
import sys
import argparse
from pathlib import Path


def should_include(path: str, excludes: re.Pattern) -> bool:
    for exclude in excludes:
        if exclude.search(path):
            return False
    return True


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("directory", nargs="?", default=".")
    parser.add_argument("--exclude", action="append", default=[])
    args = parser.parse_args()

    compiled_patterns = []
    for pattern in args.exclude:
        try:
            compiled_patterns.append(re.compile(pattern))
        except re.error as e:
            print(f"Invalid regex pattern '{pattern}': {e}", file=sys.stderr)
            sys.exit(1)

    try:
        path = Path(args.directory)
        if not path.exists():
            return []

        files = [str(file_path.relative_to(path)) for file_path in path.rglob("*.md")]
        filtered_files = [
            path for path in files if should_include(path, compiled_patterns)
        ]

        print(" ".join(filtered_files))
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
