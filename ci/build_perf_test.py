#!/usr/bin/env python3

import subprocess
import sys
import argparse


HYPERFINE_DEFAULT_SETTINGS = {
    "warmup_runs": 1,
    "prepare_command": "echo \"// dirty\" >> build.rs",
    "build_command": "cargo build",
}


def run_command(command):
    try:
        result = subprocess.run(command, shell=True, check=True)

        if result.returncode != 0:
            print(
                f"Command failed with return code: {result.returncode}", file=sys.stderr
            )
            sys.exit(result.returncode)

    except subprocess.CalledProcessError as e:
        print(f"Command failed with error: {e}", file=sys.stderr)
        sys.exit(e.returncode)


def check_tool_installed(tool_name):
    try:
        subprocess.run(
            [tool_name, "--version"],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
    except subprocess.CalledProcessError:
        print(
            f"{tool_name} is not installed. Please install it and try again.",
            file=sys.stderr,
        )
        sys.exit(1)


def hyperfine_cargo_build(settings):
    check_tool_installed("hyperfine")

    hyperfine_command = (
        f"hyperfine --warmup {settings['warmup_runs']} "
        f"--prepare '{settings['prepare_command']}' "
        f"'{settings['build_command']}'"
    )

    print(f"Running hyperfine with: {hyperfine_command}")
    run_command(hyperfine_command)


def parse_arguments():
    parser = argparse.ArgumentParser(description="Benchmark command using hyperfine.")
    parser.add_argument(
        "--warmup", type=int, help="Number of warmup runs for hyperfine (default is 1)."
    )
    parser.add_argument(
        "--prepare", type=str, help="Prepare command (default: 'cargo clean')."
    )
    parser.add_argument(
        "--build",
        type=str,
        help="Command to benchmark (default: 'cargo build').",
    )

    args = parser.parse_args()

    settings = HYPERFINE_DEFAULT_SETTINGS.copy()

    if args.warmup is not None:
        settings["warmup_runs"] = args.warmup
    if args.prepare is not None:
        settings["prepare_command"] = args.prepare
    if args.build is not None:
        settings["build_command"] = args.build

    return settings


def main():
    settings = parse_arguments()
    hyperfine_cargo_build(settings)


if __name__ == "__main__":
    main()
