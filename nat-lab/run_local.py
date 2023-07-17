#!/usr/bin/env python3

import argparse
import os
import subprocess
import sys
from typing import List, Optional, Dict, Any

PROJECT_ROOT = os.path.normpath(os.path.dirname(os.path.realpath(__file__)) + "/../..")

TEST_TIMEOUT = 80


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
        "--restart", action="store_true", help="Restart build container"
    )
    parser.add_argument(
        "-k", type=str, help="Pass the name of test case to pytest (pytest -k)"
    )
    parser.add_argument(
        "-m", type=str, help="Pass the name of mark to pytest (pytest -m)"
    )
    parser.add_argument(
        "-v",
        action="store_true",
        help="Show stdout (by default stdout is captured and not shown)",
    )
    parser.add_argument(
        "--windows",
        action="store_true",
        help="Build TCLI for Windows, run tests with 'windows' mark",
    )
    parser.add_argument(
        "--mac",
        action="store_true",
        help="Build TCLI for Mac, run tests with 'mac' mark",
    )
    parser.add_argument(
        "--linux-native", action="store_true", help="Run tests with 'linux_native' mark"
    )
    parser.add_argument("--nobuild", action="store_true", help="Don't build TCLI")
    parser.add_argument("--notests", action="store_true", help="Don't run tests")
    parser.add_argument(
        "--notypecheck", action="store_true", help="Don't run typecheck, `mypy`"
    )
    parser.add_argument("--reruns", type=int, default=0, help="Pass `reruns` to pytest")
    parser.add_argument("--moose", action="store_true", help="Build with moose")
    args = parser.parse_args()

    if not args.nobuild:
        run_build_command("linux", args)
        if args.windows:
            run_build_command("windows", args)

    if not args.notypecheck:
        run_command(["mypy", "."])

    if not args.notests:
        pytest_cmd = ["pytest", "-vv", "--durations=0", f"--reruns={args.reruns}"]

        pytest_cmd += [
            f"--timeout={TEST_TIMEOUT}",
            # Make timeout compatible with reruns
            # https://github.com/pytest-dev/pytest-rerunfailures/issues/99
            "-o",
            "timeout_func_only=true",
        ]

        pytest_cmd += get_pytest_arguments(args)

        run_command(pytest_cmd)

    return 0


def run_build_command(operating_system, args):
    command = ["../../ci/build.sh", "--default", operating_system]
    if args.restart:
        command.append("--restart")
    if args.moose:
        command.append("--moose")

    run_command(command)


def get_pytest_arguments(options) -> List[str]:
    args = []

    if options.v:
        args.extend(["--capture=no"])

    if options.k:
        args.extend(["-k", options.k])

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


if __name__ == "__main__":
    sys.exit(main())
