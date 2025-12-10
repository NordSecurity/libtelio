#!/usr/bin/env python3

import argparse
import errno
import json
import os
import shutil
import subprocess
import sys
import time
import warnings
from packaging import version
from typing import List

# isort: off
PROJECT_ROOT = os.path.normpath(os.path.dirname(os.path.realpath(__file__)) + "/..")
sys.path += [f"{PROJECT_ROOT}/ci"]
from env import LIBTELIO_ENV_NAT_LAB_DEPS_TAG  # type: ignore # pylint: disable=import-error, wrong-import-position

NATLAB_CONTAINER_RESTART_ATTEMPTS = 5


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


def start(skip_keywords=None, force_recreate=False, services_to_start=None):
    if skip_keywords is None:
        skip_keywords = []

    check_docker_version_compatibility()

    generate_grpc("../dist/linux/ens.proto")

    if "GITLAB_CI" in os.environ:
        # This is possibly a temporary solution. We observe that starting docker compose
        # takes a lot of resources. Because our pipeline starts 9 parallel nat-lab jobs
        # it sometimes happen that when the job from a previous pipeline is executed
        # on the runner, multiple new jobs start at the same time, all starting up docker
        # containers. During this startup phase the old job is experiencing timeouts.
        # We can try to offset this startup time of the parallel runs to check if it helps.
        start_delay = (int(os.environ.get("CI_NODE_INDEX", "1")) - 1) * 120
        print(f"Delaying execution for {start_delay}s to amortize the load")
        time.sleep(start_delay)
        print(f"Continuing after delay of {start_delay}s")

        with open("docker-compose.yml", "r", encoding="utf-8") as file:
            filedata = file.read()
        original_port_mapping = 'ports: ["58001"]'
        disabled_port_mapping = "ports: []"
        if original_port_mapping not in filedata:
            raise RuntimeError("Cannot find expected port mapping compose file")
        filedata = filedata.replace(original_port_mapping, disabled_port_mapping)
        with open("docker-compose.yml", "w", encoding="utf-8") as file:
            file.write(filedata)

    run_command(
        ["docker", "compose", "--profile", "base", "build", "--no-cache"],
        env={
            "COMPOSE_DOCKER_CLI_BUILD": "1",
            "DOCKER_BUILDKIT": "1",
            "LIBTELIO_ENV_NAT_LAB_DEPS_TAG": LIBTELIO_ENV_NAT_LAB_DEPS_TAG,
        },
    )

    exclude_services = set()
    try:
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
                service
                for service in services_to_start
                if service not in exclude_services
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
            command.append("--quiet-pull")
        run_command(
            command, env={"COMPOSE_DOCKER_CLI_BUILD": "1", "DOCKER_BUILDKIT": "1"}
        )
    except subprocess.CalledProcessError:
        manage_containers(services_to_start)
    else:
        manage_containers(services_to_start)


def stop():
    run_command(["docker", "compose", "down"])


def kill():
    run_command(["docker", "compose", "kill"])
    stop()


def quick_restart_container(names: List[str], env=None):
    if env:
        env = {**os.environ.copy(), **env}
    docker_status = [
        line.strip().strip("'")
        for line in subprocess.check_output(
            ["docker", "ps", "--filter", "status=running", "--format", "'{{.Names}}'"],
            env=env,
        )
        .decode("utf-8")
        .splitlines()
    ]

    for container in docker_status:
        if any(name for name in names if name in container):
            print("Killing container: ", container)
            run_command(["docker", "container", "kill", container], env=env)
    for name in names:
        print("Restarting service: ", name)
        run_command(
            [
                "docker",
                "compose",
                "up",
                "-d",
                "--wait",
                "--force-recreate",
                name,
                "--quiet-pull",
            ],
            env=env,
        )


def check_containers(services_to_start, check_only=False) -> List[str]:
    docker_status = run_command_with_output(
        ["docker", "ps", "--filter", "status=running"]
    )
    docker_status = [line.strip() for line in docker_status.splitlines()]

    missing_services: List[str] = []

    for service in services_to_start:
        if not find_container(service, docker_status):
            missing_services.append(service)
            continue

        container_ids_raw = run_command_with_output(
            ["docker", "compose", "ps", "-q", service], hide_output=True
        ).strip()
        container_ids = [
            cid.strip() for cid in container_ids_raw.splitlines() if cid.strip()
        ]

        for cid in container_ids:
            container_state_raw = run_command_with_output(
                ["docker", "inspect", cid, "--format", "{{json .State.Health}}"],
                hide_output=True,
            ).strip()

            try:
                container_state_json = (
                    None
                    if not container_state_raw or container_state_raw.lower() == "null"
                    else json.loads(container_state_raw)
                )
            except json.JSONDecodeError:
                container_state_json = None

            if isinstance(container_state_json, dict):
                status = (container_state_json.get("Status") or "").lower()
                if status == "unhealthy":
                    logs = container_state_json.get("Log") or []
                    print(f"Container {cid} is unhealthy.\nLogs: {logs}")

    # Used to call from cli
    if check_only and missing_services:
        for service in missing_services:
            run_command(["docker", "compose", "logs", service])
        raise Exception(
            f"Containers failed to start: {missing_services}; see docker logs above"
        )

    return missing_services


def manage_containers(services_to_start) -> None:
    restart_attempts = 0
    missing = []
    while restart_attempts < NATLAB_CONTAINER_RESTART_ATTEMPTS:
        missing = check_containers(services_to_start, False)
        if missing:
            print("Missing services: ", missing)
            quick_restart_container(
                missing, env={"COMPOSE_DOCKER_CLI_BUILD": "1", "DOCKER_BUILDKIT": "1"}
            )
        else:
            return
        restart_attempts += 1

    for service in missing:
        run_command(["docker", "compose", "logs", service])
    raise Exception(f"Containers failed to start: {missing}; see docker logs above")


def find_container(service: str, docker_status: List[str]) -> bool:
    for line in docker_status:
        if (service in line) and ("unhealthy" not in line):
            return True

    return False


def check_docker_version_compatibility():
    docker_version = version.parse(get_docker_version())

    with open("docker-compose.yml", "r", encoding="utf-8") as compose_file:
        compose_content = compose_file.read()
    if docker_version < version.parse("28.0") and "nat-unprotected" in compose_content:
        warnings.warn(
            f"Nat-lab uses 'unprotected nat' bridge mode which require Docker >= v28.0 (detected: v{docker_version})"
        )

        compose_content = compose_content.replace("nat-unprotected", "nat")
        shutil.copy("docker-compose.yml", "docker-compose.yml.bak")
        with open("docker-compose.yml", "w", encoding="utf-8") as compose_file:
            compose_file.write(compose_content)

        print("Docker compose backup file created: ./docker-compose.yml.bak")
        print("Changed to 'nat' bridge gateway mode")


def get_docker_version():
    try:
        result = subprocess.run(
            ["docker", "version", "--format", "{{.Server.Version}}"],
            capture_output=True,
            text=True,
            check=True,
        )
    except subprocess.CalledProcessError:
        print("Error: Docker is not installed or not running.")
        sys.exit(1)
    return result.stdout.strip()


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


def main():
    all_services = run_command_with_output(
        ["docker", "compose", "config", "--services"], hide_output=True
    )
    valid_services = [service.strip() for service in all_services.splitlines()]
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    start_parser = subparsers.add_parser(
        "start",
        help="Build and start the environment [--skip-fullcone] [--skip-windows] [--skip-windows-client-02] [--skip-mac] [--skip-nlx] [--lite-mode]",
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
        choices=valid_services,
        help="List of services to start",
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
        skip_keywords = set()
        if args.lite_mode:
            skip_keywords.update(["fullcone", "windows", "mac", "nlx", "openwrt"])
        else:
            if args.skip_fullcone:
                skip_keywords.add("fullcone")
            if args.skip_windows:
                skip_keywords.add("windows")
            if args.skip_windows_1:
                skip_keywords.update(
                    ["windows-client-01", "windows-gw-01", "windows-gw-02"]
                )
            if args.skip_windows_2:
                skip_keywords.update(
                    ["windows-client-02", "windows-gw-03", "windows-gw-04"]
                )
            if args.skip_mac:
                skip_keywords.add("mac")
            if args.skip_nlx:
                skip_keywords.add("nlx")
            if args.skip_openwrt:
                skip_keywords.add("openwrt")
        if args.services_to_start:
            services_to_start = args.services_to_start
            start(skip_keywords, services_to_start=services_to_start)
        else:
            start(skip_keywords)
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
        check_containers(services_to_start=valid_services, check_only=True)


if __name__ == "__main__":
    main()
