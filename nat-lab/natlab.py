#!/usr/bin/env python3

from typing import List
import argparse
import subprocess
import os


def run_command(command, env=None):
    if env:
        env = {**os.environ.copy(), **env}

    print("|EXECUTE| {}".format(" ".join(command)))
    subprocess.check_call(command, env=env)
    print("")


def run_command_with_output(command, hide_output=False):
    print("|EXECUTE| {}".format(" ".join(command)))
    result = subprocess.check_output(command).decode("utf-8")
    if hide_output:
        print("(OUTPUT HIDDEN)")
    else:
        print(result)
        print("")
    return result


def start():
    run_command(["./build_derp.sh", "--check-norebuild"])
    run_command(["./build_wireguard-go.sh", "--check-norebuild"])
    run_command(
        ["docker", "compose", "--profile", "base", "build", "--no-cache"],
        env={"COMPOSE_DOCKER_CLI_BUILD": "1", "DOCKER_BUILDKIT": "1"},
    )
    run_command(
        ["docker", "compose", "up", "-d"],
        env={"COMPOSE_DOCKER_CLI_BUILD": "1", "DOCKER_BUILDKIT": "1"},
    )

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
