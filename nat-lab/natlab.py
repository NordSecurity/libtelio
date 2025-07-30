#!/usr/bin/env python3

import argparse
import os
import shutil
import subprocess
import sys
import warnings
from packaging import version
from typing import List

# isort: off
PROJECT_ROOT = os.path.normpath(os.path.dirname(os.path.realpath(__file__)) + "/..")
sys.path += [f"{PROJECT_ROOT}/ci"]
from env import LIBTELIO_ENV_NAT_LAB_DEPS_TAG  # type: ignore # pylint: disable=import-error, wrong-import-position


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


def start():
    check_docker_version_compatibility()

    original_port_mapping = 'ports: ["58001"]'
    disabled_port_mapping = "ports: []"
    with open("docker-compose.yml", "r", encoding="utf-8") as file:
        filedata = file.read()
    if original_port_mapping not in filedata:
        raise RuntimeError("Cannot find expected port mapping compose file")
    if "GITLAB_CI" in os.environ:
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
    try:
        run_command(
            ["docker", "compose", "up", "-d", "--wait"],
            env={"COMPOSE_DOCKER_CLI_BUILD": "1", "DOCKER_BUILDKIT": "1"},
        )
    except subprocess.CalledProcessError:
        check_containers()
    else:
        check_containers()


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
            subprocess.run(["docker", "restart", container, "-t", "0"], env=env)


def check_containers() -> None:
    services = run_command_with_output(["docker", "compose", "config", "--services"])
    services = [service.strip() for service in services.splitlines()]

    docker_status = run_command_with_output(
        ["docker", "ps", "--filter", "status=running"]
    )
    openwrt_container_log = run_command_with_output(["docker", "compose", "logs", "openwrt-gw-01"])
    print(openwrt_container_log)
    docker_status = [line.strip() for line in docker_status.splitlines()]

    missing_services: List[str] = []

    for service in services:
        if not find_container(service, docker_status):
            run_command(["docker", "compose", "logs", service])
            missing_services.append(service)

    if missing_services:
        raise Exception(
            f"Containers failed to start: {missing_services}; see docker logs above"
        )


def find_container(service: str, docker_status: List[str]) -> bool:
    for line in docker_status:
        if line.find(service) >= 0:
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


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--start", action="store_true", help="Build and start the environment"
    )
    parser.add_argument("--stop", action="store_true", help="Stop the environment")
    parser.add_argument("--kill", action="store_true", help="Kill the environment")
    parser.add_argument(
        "--restart", action="store_true", help="Kill and start the environment"
    )
    parser.add_argument(
        "--check-containers",
        action="store_true",
        help="Check if all containers are running",
    )

    args = parser.parse_args()

    if args.start:
        start()
    elif args.stop:
        stop()
    elif args.kill:
        kill()
    elif args.restart:
        kill()
        start()
    elif args.check_containers:
        check_containers()


if __name__ == "__main__":
    main()
