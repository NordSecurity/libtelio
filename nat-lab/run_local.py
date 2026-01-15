#!/usr/bin/env python3

"""
NAT Lab Test Runner

This script provides a flexible and configurable way to run NAT lab tests with
support for various modes of execution, including:
- CI environment handling
- Test duration tracking
- Distributed test splitting
- Performance test support

Key improvements:
- Centralized test running logic
- Enhanced CI environment detection
- Dynamic test splitting and duration tracking
- Simplified test configuration
"""

import argparse
import json
import os
import subprocess
import sys
import time

# Import distributed duration tracker
from distributed_duration_tracker import DistributedDurationTracker
from typing import List, Optional, Dict, Any

PROJECT_ROOT = os.path.normpath(os.path.dirname(os.path.realpath(__file__)) + "/../..")

# Add path for local modules
# Adjust Python path to include current directory and parent directory
# Add current directory to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


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
        "--splits", type=int, default=1, help="Number of test splitting groups"
    )
    parser.add_argument(
        "--group",
        type=int,
        default=0,
        help="Current group for test splitting (0-indexed)",
    )
    parser.add_argument(
        "--splits-duration",
        type=str,
        help="Path to JSON file with test duration data for balanced splitting",
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
    parser.add_argument(
        "--save-node-durations",
        action="store_true",
        help="Save test duration data to a node-specific JSON file",
    )
    parser.add_argument(
        "--compile-durations",
        action="store_true",
        help="Compile test duration data from all node files",
    )
    parser.add_argument(
        "--ci-mode",
        action="store_true",
        help="Enable additional CI-specific test running behaviors",
    )
    args = parser.parse_args()

    # Enhanced setup verification control
    if not args.no_verify_setup_correctness:
        verify_setup_correctness()

    # Additional CI mode checks
    if args.ci_mode:
        # Validate CI-specific environment requirements
        if os.environ.get("GITLAB_CI") == "true":
            required_env_vars = [
                "CI_NODE_INDEX",
                "CI_NODE_TOTAL",
                "CI_REGISTRY_USER",
                "CI_JOB_TOKEN",
                "CI_REGISTRY",
            ]
            missing_vars = [var for var in required_env_vars if not os.environ.get(var)]

            if missing_vars:
                print(
                    f"Warning: Missing CI environment variables: {', '.join(missing_vars)}",
                    file=sys.stderr,
                )
                # Optionally raise an exception or handle gracefully

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

        report_file = "report.json"
        if os.environ.get("GITLAB_CI") == "true":
            pytest_cmd.extend(["--json-report", f"--json-report-file={report_file}"])

        pytest_cmd += get_pytest_arguments(args)

        # Add test splitting arguments if specified
        # Note: Don't adjust for group index here, as it should be passed as-is
        if hasattr(args, "splits") and args.splits > 1:
            pytest_cmd.extend([f"--splits={args.splits}", f"--group={args.group}"])
            if args.splits_duration:
                pytest_cmd.append(f"--splits-duration={args.splits_duration}")

        test_dir = "performance_tests" if args.perf_tests else "tests"
        pytest_cmd.append(test_dir)

        run_command(pytest_cmd)

        # Handle duration tracking for CI environment or explicit save request
        if os.environ.get("GITLAB_CI") == "true" or args.save_node_durations:
            # Initialize duration tracker
            duration_tracker = DistributedDurationTracker()

            # Always define test_durations as an empty dict
            test_durations: Dict[str, float] = {}

            # Attempt to save node durations
            try:
                # Check if file exists and is not empty
                if os.path.exists(report_file) and os.path.getsize(report_file) > 0:
                    with open(report_file, "r") as f:
                        # Use a safe parsing method
                        report = json.load(f)

                        # Extract test durations from the report
                        test_durations = {
                            str(test.get("nodeid", "unknown")): float(
                                test.get("duration", 0.0)
                            )
                            for test in report.get("tests", [])
                            if test.get("duration") is not None
                        }
                else:
                    print(
                        f"No test duration report found at {report_file}",
                        file=sys.stderr,
                    )

                # Attempt to save node durations
                if test_durations:
                    duration_tracker.save_node_durations(test_durations)
                    print("Node-specific test durations saved.")
                else:
                    print("No test durations to save.", file=sys.stderr)

            except Exception as e:
                print(f"Error processing test durations: {e}", file=sys.stderr)
                # Always attempt to save, even with an empty dict
                duration_tracker.save_node_durations(test_durations)

            # Compile durations if requested or on the last node
            if args.compile_durations or (
                os.environ.get("GITLAB_CI") == "true"
                and os.environ.get("CI_NODE_INDEX") == os.environ.get("CI_NODE_TOTAL")
            ):
                try:
                    duration_tracker.compile_durations()
                    print("Test durations compiled successfully.")
                except Exception as e:
                    print(f"Error compiling test durations: {e}", file=sys.stderr)

                    # Save node-specific durations
                    duration_tracker.save_node_durations(test_durations)
                    print("Node-specific test durations saved successfully.")
                except (IOError, json.JSONDecodeError, KeyError) as e:
                    print(
                        f"Warning: Failed to save test durations: {e}", file=sys.stderr
                    )

            # Compile durations if flag is set or on the last node
            if args.compile_durations or (
                os.environ.get("CI_NODE_INDEX") == os.environ.get("CI_NODE_TOTAL")
            ):
                duration_tracker.compile_durations()
                print("Test durations compiled successfully.")

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
