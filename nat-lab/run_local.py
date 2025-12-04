#!/usr/bin/env python3

import argparse
import os
import subprocess
import sys
import time
from typing import List, Optional, Dict, Any

PROJECT_ROOT = os.path.normpath(os.path.dirname(os.path.realpath(__file__)) + "/../..")

TEST_TIMEOUT = 180


# Runs the command with stdout and stderr piped back to executing shell (this results
# in real time log messages that are properly color coded)
def run_command(command: List[str], env: Optional[Dict[str, Any]] = None) -> None:
    if env:
        env = {**os.environ.copy(), **env}

    print(f"|EXECUTE| {' '.join(command)}")
    subprocess.check_call(command, env=env)
    print("")


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

        pytest_cmd += get_pytest_arguments(args)

        test_dir = "performance_tests" if args.perf_tests else "tests"
        pytest_cmd.append(test_dir)

        run_command(pytest_cmd)

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
