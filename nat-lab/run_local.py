#!/usr/bin/env python3

import argparse
import json
import os
import subprocess
import sys
import time
from pathlib import Path
from typing import List, Optional, Dict, Any

PROJECT_ROOT = os.path.normpath(os.path.dirname(os.path.realpath(__file__)) + "/../..")

TEST_TIMEOUT = 180


def load_json(file_path: Path) -> Dict:
    """Safely load JSON file."""
    if not file_path.exists():
        return {}
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            return json.load(f)
    except (json.JSONDecodeError, IOError):
        return {}


def save_json(file_path: Path, data: Dict) -> None:
    """Safely save JSON file."""
    with open(file_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)


def calculate_duration_delta(original: Dict, merged: Dict) -> Dict:
    """
    Calculate what's new/changed between original and merged durations.
    Returns only tests that are new or have different durations.
    """
    new_data = {}
    for test_name, duration in merged.items():
        if test_name not in original or original[test_name] != duration:
            new_data[test_name] = duration
    return new_data


# Runs the command with stdout and stderr piped back to executing shell (this results
# in real time log messages that are properly color coded)
def run_command(
    command: List[str],
    env: Optional[Dict[str, Any]] = None,
    allow_failure: bool = False,
) -> int:
    if env:
        env = {**os.environ.copy(), **env}

    print(f"|EXECUTE| {' '.join(command)}")
    result = subprocess.run(command, env=env)
    print("")
    if result.returncode != 0 and not allow_failure:
        raise subprocess.CalledProcessError(result.returncode, command)
    return result.returncode


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-o", type=str, default="linux", help="Pass the host OS [default: linux])"
    )
    parser.add_argument(
        "--restart", action="store_true", help="Restart build container"
    )
    parser.add_argument(
        "-k", type=str, help="Pass the name of test case to pytest (pytest -k)"
    )
    parser.add_argument(
        "-m", type=str, help="Pass the name of mark to pytest (pytest -m)"
    )
    parser.add_argument(
        "-x", action="store_true", help="Stop tests on first failure or error"
    )
    parser.add_argument(
        "-v",
        action="store_true",
        help="Show stdout (by default stdout is captured and not shown)",
    )
    parser.add_argument(
        "--windows",
        action="store_true",
        help="Windows build, run tests with 'windows' mark",
    )
    parser.add_argument(
        "--mac",
        action="store_true",
        help="MacOS build, run tests with 'mac' mark",
    )
    parser.add_argument(
        "--linux-native", action="store_true", help="Run tests with 'linux_native' mark"
    )
    parser.add_argument(
        "--utils", action="store_true", help="Run tests with 'utils' mark"
    )
    parser.add_argument("--nobuild", action="store_true", help="Don't build libtelio")
    parser.add_argument("--notests", action="store_true", help="Don't run tests")
    parser.add_argument(
        "--notypecheck", action="store_true", help="Don't run typecheck, `mypy`"
    )
    parser.add_argument("--reruns", type=int, default=0, help="Pass `reruns` to pytest")
    parser.add_argument("--count", type=int, default=1, help="Pass `count` to pytest")
    parser.add_argument("--moose", action="store_true", help="Build with moose")
    parser.add_argument(
        "--input-durations",
        type=str,
        help="Path to input duration file (read-only reference for splitting)",
    )
    parser.add_argument(
        "--output-durations",
        type=str,
        help="Path to output duration file (where new durations are stored)",
    )
    parser.add_argument(
        "--no-verify-setup-correctness",
        action="store_true",
        help="Disable verification of setup correctness",
    )
    parser.add_argument(
        "--telio-debug",
        action="store_true",
        help="Use libtelio debug build binaries",
    )
    parser.add_argument(
        "--perf-tests",
        action="store_true",
        help="Run performance tests instead of functional tests",
    )
    args = parser.parse_args()

    if not args.no_verify_setup_correctness:
        verify_setup_correctness()

    if not args.nobuild:
        print("\u001b[33m")
        print("|=======================================================|")
        print("| WARNING! Running builds requires atleast 16GBs of RAM |")
        print("|                                                       |")
        print(
            "| or set env variable \033[1mNATLAB_REDUCE_PARALLEL_LINKERS=1\033[0m\u001b[33m  |"
        )
        print("|=======================================================|")
        print("\u001b[0m")
        try:
            run_build_command("linux", args)
            # Run windows tests on WinVM
            if args.windows:
                run_build_command("windows", args)
            # Run nat-lab natively on macOS (TODO: Add windows support)
            if args.o == "darwin":
                run_build_command("darwin", args)
        except subprocess.CalledProcessError:
            print("\u001b[31m")
            print(
                "|===================================================================|"
            )
            print(
                "| ERROR! If build failed by getting SIGKILL, it might               |"
            )
            print(
                "| ERROR! be due to lack of RAM. Build requires atleast 16GBs of RAM |"
            )
            print(
                "|                                                                   |"
            )
            print(
                "|       or set env variable \033[1mNATLAB_REDUCE_PARALLEL_LINKERS=1\033[0m\u001b[31m        |"
            )
            print(
                "|===================================================================|"
            )
            print("\u001b[0m")
            raise

    if not args.notypecheck:
        run_command(["uv", "run", "mypy", "."])

    if not args.notests:
        pytest_cmd = [
            "pytest",
            "-vv",
            "--durations=0",
            f"--reruns={args.reruns}",
            f"--count={args.count}",
        ]

        pytest_cmd += [
            f"--timeout={TEST_TIMEOUT}",
            # Make timeout compatible with reruns
            # https://github.com/pytest-dev/pytest-rerunfailures/issues/99
            "-o",
            "timeout_func_only=true",
        ]

        pytest_opts = os.environ.get("PYTEST_ADDOPTS", "")
        original_durations_data = {}
        input_path = None

        if "splits" in pytest_opts:
            if args.input_durations:
                input_path = Path(args.input_durations)
                original_durations_data = load_json(input_path)
                pytest_cmd.extend([
                    "--store-durations",
                    f"--durations-path={input_path.absolute()}",
                    "--splitting-algorithm=least_duration",
                ])
            elif args.output_durations:
                output_path = Path(args.output_durations)
                pytest_cmd.extend([
                    "--store-durations",
                    f"--durations-path={output_path.absolute()}",
                    "--splitting-algorithm=least_duration",
                ])

        pytest_cmd += get_pytest_arguments(args)

        test_dir = "performance_tests" if args.perf_tests else "tests"
        pytest_cmd.append(test_dir)

        pytest_result = run_command(pytest_cmd, allow_failure=True)

        if "splits" in pytest_opts and args.output_durations and args.input_durations:
            output_path = Path(args.output_durations)
            if input_path:
                merged_data = load_json(input_path)
                new_data = calculate_duration_delta(
                    original_durations_data, merged_data
                )
                save_json(output_path, new_data)
                save_json(input_path, original_durations_data)

        if pytest_result != 0:
            raise subprocess.CalledProcessError(pytest_result, pytest_cmd)

    return 0


def run_build_command(operating_system, args):
    if operating_system == "darwin":
        command = [
            "../ci/build_libtelio.py",
            "build",
            "macos",
            "aarch64",
        ]
    else:
        command = [
            "../../ci/build.sh",
            "--default",
            operating_system,
        ]
    command.extend(["--uniffi-test-bindings"])
    if args.telio_debug:
        command.append("--debug")
    if args.restart:
        command.append("--restart")
    if args.moose:
        command.append("--moose")

    run_command(command)


def get_pytest_arguments(options) -> List[str]:
    args = []

    if options.telio_debug:
        os.environ["TELIO_BIN_PROFILE"] = "debug"
    else:
        os.environ["TELIO_BIN_PROFILE"] = "release"

    if options.v:
        args.extend(["--capture=no"])

    if options.k:
        args.extend(["-k", options.k])

    if options.x:
        args.extend(["-x"])

    if options.m:
        args.extend(["-m", options.m])
    else:
        marks = (
            "not nat and not windows and not mac and not linux_native and not long and"
            " not moose"
        )
        if options.windows:
            marks = marks.replace("not windows", "windows")
        if options.mac:
            marks = marks.replace("not mac", "mac")
        if options.linux_native:
            marks = marks.replace("not linux_native", "linux_native")
        if options.moose:
            marks = marks.replace("and not moose", "")
        args.extend(["-m", marks])

    return args


# Verifies that setup for natlab is correct.
def verify_setup_correctness():
    def get_tag_or_hash_of_dir(path):
        result = subprocess.run(
            ["git", "tag", "--points-at", "HEAD"], cwd=path, capture_output=True
        )
        if result.returncode != 0:
            return None
        tag = result.stdout.decode("ascii").strip()
        if tag != "":
            return tag

        result = subprocess.run(
            ["git", "rev-parse", "HEAD"], cwd=path, capture_output=True
        )
        if result.returncode != 0:
            return None
        return result.stdout.decode("ascii").strip()

    def get_expected_tag():
        with open("../.github/workflows/gitlab.yml", "r", encoding="utf-8") as f:
            lines = [line.strip() for line in f if "triggered-ref" in line]
            if len(lines) == 0:
                return None
            line = lines[0]
            values = line.split(" ")
            if len(values) != 2:
                return None
            return values[1]

    actual = get_tag_or_hash_of_dir(PROJECT_ROOT)
    if actual is None:
        return
    expected_tag = get_expected_tag()
    if expected_tag is None:
        return
    if expected_tag != actual:
        print(
            "################################################################################"
        )
        print(
            f"Project root ({PROJECT_ROOT}) and 'triggered-ref' in"
            " ../.github/workflows/gitlab.yml differ"
        )
        print(f"        '{actual}' vs '{expected_tag}'")
        print("!!! Nat-lab might not behave correctly !!!")
        print(
            "################################################################################"
        )
        time.sleep(5)


if __name__ == "__main__":
    sys.exit(main())
