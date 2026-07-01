#!/usr/bin/env python3

import argparse
import errno
import json
import os
import subprocess
import sys
from typing import List, Tuple

# isort: off
PROJECT_ROOT = os.path.normpath(os.path.dirname(os.path.realpath(__file__)) + "/..")
sys.path += [f"{PROJECT_ROOT}/ci"]
from env import LIBTELIO_ENV_NAT_LAB_DEPS_TAG  # type: ignore # pylint: disable=import-error, wrong-import-position

NATLAB_CONTAINER_RESTART_ATTEMPTS = 5


def disable_client_host_ports():
    """Drop the client host-port binding in CI by editing docker-compose.yml in place.

    Idempotent: a no-op if the binding is already disabled, so repeated runs on the
    same checkout don't fail.
    """
    with open("docker-compose.yml", "r", encoding="utf-8") as file:
        filedata = file.read()
    enabled = 'ports: ["58001"]'
    disabled = "ports: []"
    if enabled in filedata:
        filedata = filedata.replace(enabled, disabled)
        with open("docker-compose.yml", "w", encoding="utf-8") as file:
            file.write(filedata)
    elif disabled not in filedata:
        raise RuntimeError("Cannot find expected client port mapping in compose file")


def compose_container_ids(service: str, running_only: bool = False) -> List[str]:
    """Resolve a compose service to its concrete container IDs (exact, no substring match)."""
    command = ["docker", "compose", "ps", "-q"]
    command += ["--status", "running"] if running_only else ["--all"]
    command.append(service)
    output = run_command_with_output(command, hide_output=True)
    return [cid.strip() for cid in output.splitlines() if cid.strip()]


def inspect_health(container_id: str):
    raw = run_command_with_output(
        ["docker", "inspect", container_id, "--format", "{{json .State.Health}}"],
        hide_output=True,
    ).strip()
    if not raw or raw.lower() == "null":
        return None
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return None
    if isinstance(data, dict):
        return (data.get("Status") or "").lower()
    return None


def run_command(command, env=None):
    if env:
        env = {**os.environ.copy(), **env}

    print(f"|EXECUTE| {' '.join(command)}")
    subprocess.check_call(command, env=env)
    print("")


def run_command_with_output(command, hide_output=False):
    print(f"|EXECUTE| {' '.join(command)}")
    result = subprocess.check_output(command).decode("utf-8")
    if hide_output:
        print("(OUTPUT HIDDEN)")
    else:
        print(result)
        print("")
    return result


def dump_docker_logs(service_name):
    """Dump the last 200 lines of docker compose logs for a failing service."""
    print(f"\n=== Docker logs for {service_name} ===")
    result = subprocess.run(
        ["docker", "compose", "logs", "--tail", "200", service_name],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.stdout:
        print(result.stdout)
    if result.stderr:
        print(result.stderr)
    print(f"=== End of docker logs for {service_name} ===\n")


def dump_journal_logs(service_name):
    """Dump the last 200 lines of systemd journal logs from inside the container(s) for a service."""
    try:
        result = subprocess.run(
            ["docker", "compose", "ps", "-q", service_name],
            capture_output=True,
            text=True,
            check=False,
        )
        container_ids = [
            cid.strip() for cid in result.stdout.splitlines() if cid.strip()
        ]
    except (subprocess.SubprocessError, OSError) as e:
        print(f"Could not retrieve container IDs for {service_name}: {e}")
        return

    for container_id in container_ids:
        # Check if journalctl exists in the container
        try:
            check_result = subprocess.run(
                ["docker", "exec", container_id, "sh", "-c", "command -v journalctl"],
                capture_output=True,
                text=True,
                check=False,
            )
            if check_result.returncode != 0:
                print(
                    f"journalctl not found in container {container_id} for service {service_name}, skipping journal log dump"
                )
                continue
        except (subprocess.SubprocessError, OSError) as e:
            print(f"Could not check for journalctl in container {container_id}: {e}")
            continue

        print(
            f"\n=== Systemd journal logs for {service_name} (container {container_id}) ==="
        )
        try:
            result = subprocess.run(
                [
                    "docker",
                    "exec",
                    container_id,
                    "journalctl",
                    "--no-pager",
                    "-n",
                    "200",
                ],
                capture_output=True,
                text=True,
                check=False,
            )
            if result.stdout:
                print(result.stdout)
            if result.stderr:
                print(result.stderr)
        except (subprocess.SubprocessError, OSError) as e:
            print(
                f"Could not retrieve journal logs for {service_name} (container {container_id}): {e}"
            )
        print(
            f"=== End of systemd journal logs for {service_name} (container {container_id}) ===\n"
        )


def start(
    skip_keywords=None, force_recreate=False, services_to_start=None, rebuild=False
):
    if skip_keywords is None:
        skip_keywords = []

    generate_grpc("../dist/linux/ens.proto")

    if "GITLAB_CI" in os.environ:
        disable_client_host_ports()

    build_command = ["docker", "compose", "--profile", "base", "build"]
    # Build from cache locally for fast iteration. In CI always force a clean
    # rebuild so images are fully reproducible and never reuse a persisted layer.
    if rebuild or "NATLAB_BUILD_NO_CACHE" in os.environ or "GITLAB_CI" in os.environ:
        build_command.append("--no-cache")

    run_command(
        build_command,
        env={
            "COMPOSE_DOCKER_CLI_BUILD": "1",
            "DOCKER_BUILDKIT": "1",
            "LIBTELIO_ENV_NAT_LAB_DEPS_TAG": LIBTELIO_ENV_NAT_LAB_DEPS_TAG,
        },
    )

    exclude_services = set()
    all_services = run_command_with_output(
        ["docker", "compose", "config", "--services"], hide_output=True
    )
    all_services = [service.strip() for service in all_services.splitlines()]

    exclude_services = set(
        filter(
            lambda service: any(keyword in service for keyword in skip_keywords),
            all_services,
        )
    )

    if services_to_start is not None:
        services_to_start = [
            service for service in services_to_start if service not in exclude_services
        ]
    else:
        services_to_start = [
            service for service in all_services if service not in exclude_services
        ]

    if exclude_services:
        print(f"Skipping services: {sorted(exclude_services)}")

    command = ["docker", "compose", "up", "-d", "--wait"]
    if force_recreate:
        command += ["--force-recreate"]

    command += services_to_start

    if "GITLAB_CI" in os.environ:
        try:
            run_command(["sudo", "mount", "-t", "debugfs", "none", "/sys/kernel/debug"])
            run_command([
                "sudo",
                "sh",
                "-c",
                "echo 'module wireguard +p' > /sys/kernel/debug/dynamic_debug/control",
            ])
        except subprocess.CalledProcessError as e:
            print(f"Enabling WireGuard dynamic debug failed: {e}")

        command.append("--quiet-pull")
    try:
        run_command(
            command, env={"COMPOSE_DOCKER_CLI_BUILD": "1", "DOCKER_BUILDKIT": "1"}
        )
    except subprocess.CalledProcessError as e:
        print(
            f"WARNING: 'docker compose up --wait' failed with exit code {e.returncode}"
        )
        print("Will attempt to diagnose and recover via manage_containers()...")

    manage_containers(services_to_start)


def stop():
    if "GITLAB_CI" in os.environ:
        try:
            run_command([
                "sudo",
                "sh",
                "-c",
                "echo 'module wireguard -p' > /sys/kernel/debug/dynamic_debug/control",
            ])
        except subprocess.CalledProcessError as e:
            print(f"Could not disable WireGuard dynamic debug: {e}")

    run_command(["docker", "compose", "down"])


def kill():
    run_command(["docker", "compose", "kill"])
    stop()


def quick_restart_container(names: List[str], env=None):
    if env:
        env = {**os.environ.copy(), **env}

    for service in names:
        for cid in compose_container_ids(service, running_only=True):
            print("Killing container: ", cid)
            run_command(["docker", "container", "kill", cid], env=env)
    print("Restarting services: ", names)
    try:
        run_command(
            [
                "docker",
                "compose",
                "up",
                "-d",
                "--wait",
                "--force-recreate",
                # Recreate only the failed services, not their healthy dependencies
                # (which include the slow-to-boot VMs).
                "--no-deps",
            ]
            + names
            + ["--quiet-pull"],
            env=env,
        )
    except subprocess.CalledProcessError as e:
        print(f"Restart of services '{names}' failed with exit code {e.returncode}")


def _report_container_failures(
    missing_services: List[str], unhealthy_services: List[str]
) -> None:
    failed = missing_services + [
        s for s in unhealthy_services if s not in missing_services
    ]
    if not failed:
        return
    # Dump logs at the end for CLI check
    for service in missing_services:
        dump_docker_logs(service)
    for service in unhealthy_services:
        dump_docker_logs(service)
        dump_journal_logs(service)
    raise RuntimeError(f"Containers failed to start: {failed}; see docker logs above")


def find_failing_containers(services_to_start) -> Tuple[List[str], List[str]]:
    missing_services: List[str] = []
    unhealthy_services: List[str] = []

    for service in services_to_start:
        running_ids = compose_container_ids(service, running_only=True)
        if not running_ids:
            missing_services.append(service)
            continue
        for cid in running_ids:
            if inspect_health(cid) == "unhealthy":
                if service not in unhealthy_services:
                    unhealthy_services.append(service)
                break

    return missing_services, unhealthy_services


def check_containers(services_to_start) -> None:
    missing, unhealthy = find_failing_containers(services_to_start)
    _report_container_failures(missing, unhealthy)


def manage_containers(services_to_start) -> None:
    restart_attempts = 0
    while restart_attempts < NATLAB_CONTAINER_RESTART_ATTEMPTS:
        missing, unhealthy = find_failing_containers(services_to_start)
        failed = missing + [s for s in unhealthy if s not in missing]
        if not failed:
            return
        print("Missing services: ", missing)
        print("Unhealthy services: ", unhealthy)
        quick_restart_container(
            failed, env={"COMPOSE_DOCKER_CLI_BUILD": "1", "DOCKER_BUILDKIT": "1"}
        )
        restart_attempts += 1

    # Dump logs and raise for any containers still failing after all attempts.
    check_containers(services_to_start)


def generate_grpc(path):
    os.makedirs("bin/grpc_protobuf", exist_ok=True)
    include = os.path.dirname(path)
    if not os.path.exists(path):
        print(
            f"You need to have {path} generated. You can do it by building libtelio, for example with:"
        )
        print("\n\tuv run ./run_local.py --notests\n")
        raise FileNotFoundError(errno.ENOENT, os.strerror(errno.ENOENT), path)
    run_command([
        "python3",
        "-m",
        "grpc_tools.protoc",
        f"-I{include}",
        "--python_out=./bin/grpc_protobuf/",
        "--grpc_python_out=./bin/grpc_protobuf",
        path,
    ])


def restart():
    """Restart existing containers (only restarts running containers)"""
    run_command(["docker", "compose", "restart"])


def recreate():
    """Recreate existing containers (only recreates running containers)"""
    running_services = run_command_with_output(
        ["docker", "compose", "ps", "-a", "--services"], True
    ).splitlines()
    all_services = run_command_with_output(
        ["docker", "compose", "config", "--services"], True
    ).splitlines()
    exclude_services = set(all_services) - set(running_services)
    start(exclude_services, True)


def recreate_all():
    """Recreate all containers"""
    start(None, True)


def _resolve_skip_keywords(args) -> set:
    if args.lite_mode:
        return {"fullcone", "windows", "mac", "nlx", "openwrt"}
    skip_keywords: set = set()
    if args.skip_fullcone:
        skip_keywords.add("fullcone")
    if args.skip_windows:
        skip_keywords.add("windows")
    if args.skip_windows_1:
        skip_keywords.update(["windows-client-01", "windows-gw-01", "windows-gw-02"])
    if args.skip_windows_2:
        skip_keywords.update(["windows-client-02", "windows-gw-03", "windows-gw-04"])
    if args.skip_mac:
        skip_keywords.add("mac")
    if args.skip_nlx:
        skip_keywords.add("nlx")
    if args.skip_openwrt:
        skip_keywords.add("openwrt")
    return skip_keywords


def list_services() -> List[str]:
    output = run_command_with_output(
        ["docker", "compose", "config", "--services"], hide_output=True
    )
    return [service.strip() for service in output.splitlines() if service.strip()]


def main():
    parser = argparse.ArgumentParser(
        description="Build, start and manage the nat-lab docker/VM test environment."
    )
    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    start_parser = subparsers.add_parser(
        "start",
        help="Build and start the environment (run `start --help` for skip/scope flags)",
    )
    start_parser.add_argument(
        "--skip-fullcone",
        action="store_true",
        help="Skip starting fullcone related containers (fullcone-client-*, fullcone-gw-*)",
    )
    start_parser.add_argument(
        "--skip-windows",
        action="store_true",
        help="Skip starting all windows related containers (windows-client-*, windows-gw-*)",
    )
    start_parser.add_argument(
        "--skip-windows-1",
        action="store_true",
        help="Skip starting windows-client-01 container and related gateways",
    )
    start_parser.add_argument(
        "--skip-windows-2",
        action="store_true",
        help="Skip starting windows-client-02 container and related gateways",
    )
    start_parser.add_argument(
        "--skip-mac",
        action="store_true",
        help="Skip starting mac-client-01 container and related gateways",
    )
    start_parser.add_argument(
        "--skip-nlx", action="store_true", help="Skip starting nlx-01 container"
    )
    start_parser.add_argument(
        "--skip-openwrt",
        action="store_true",
        help="Skip starting openwrt related containers",
    )
    start_parser.add_argument(
        "--lite-mode",
        action="store_true",
        help="Skip all heavy containers (windows, mac, fullcone and nlx)",
    )

    start_parser.add_argument(
        "--services-to-start",
        nargs="+",
        metavar="SERVICE",
        help="Start only these services (validated against the compose file)",
    )
    start_parser.add_argument(
        "--rebuild",
        action="store_true",
        help="Force a no-cache rebuild of the base image (same as NATLAB_BUILD_NO_CACHE=1)",
    )

    subparsers.add_parser("restart", help="Restart (already existing) containers")
    subparsers.add_parser("recreate", help="Recreate (already existing) containers")
    subparsers.add_parser("recreate-all", help="Recreate all containers")
    subparsers.add_parser("stop", help="Stop the environment")
    subparsers.add_parser("kill", help="Kill the environment")
    subparsers.add_parser(
        "check-containers", help="Check if all containers are running"
    )

    args = parser.parse_args()
    if not args.command:
        parser.print_help()
        return

    if args.command == "start":
        skip_keywords = _resolve_skip_keywords(args)
        if args.services_to_start:
            valid_services = list_services()
            invalid = [s for s in args.services_to_start if s not in valid_services]
            if invalid:
                start_parser.error(
                    "unknown service(s) for --services-to-start: "
                    f"{', '.join(invalid)}\n"
                    f"valid services: {', '.join(sorted(valid_services))}"
                )
            start(
                skip_keywords,
                services_to_start=args.services_to_start,
                rebuild=args.rebuild,
            )
        else:
            start(skip_keywords, rebuild=args.rebuild)
    elif args.command == "restart":
        restart()
    elif args.command == "recreate":
        recreate()
    elif args.command == "recreate-all":
        recreate_all()
    elif args.command == "stop":
        stop()
    elif args.command == "kill":
        kill()
    elif args.command == "check-containers":
        check_containers(services_to_start=list_services())


if __name__ == "__main__":
    main()
