import argparse
import subprocess
import os
import shutil
import importlib
from typing import Any
from dataclasses import dataclass
from rust_build_utils.rust_utils_config import GLOBAL_CONFIG

NAME = os.getenv("NAME")
VERSION = os.getenv("VERSION")
PROJECT_ROOT = os.getenv("PROJECT_ROOT")
WORKING_DIR = os.getenv("WORKING_DIR")


assert (
    NAME
), "NAME var is missing, add it to your build_lib{name}.py file. If you need an example, check ci-helper-scripts/rust_sample/ci/build_sample.py"
assert VERSION, f"VERSION var is missing, add it to your build_lib{NAME}.py file"
assert (
    PROJECT_ROOT
), f"PROJECT_ROOT var is missing, add it to your build_lib{NAME}.py file"

if WORKING_DIR is not None:
    os.chdir(WORKING_DIR)
else:
    os.chdir(PROJECT_ROOT)

DISTRIBUTION_DIR = os.path.normpath(PROJECT_ROOT + "/dist/")
TARGET_DIR = (
    os.path.normpath(WORKING_DIR + "/target/")
    if WORKING_DIR is not None
    else os.path.normpath(PROJECT_ROOT + "/target/")
)
LIPO_TARGET_OSES = ["macos", "ios"]


def concatenate_env_variable(env_var: str, value_array):
    for value in value_array:
        os.environ[env_var] += value


def clear_env_variables(config):
    if "env" in GLOBAL_CONFIG[config.target_os]:
        for key, value in GLOBAL_CONFIG[config.target_os]["env"].items():
            if value[1] == "set":
                os.environ[key] = ""
    if "env" in GLOBAL_CONFIG[config.target_os]["archs"][config.arch]:
        for key, value in GLOBAL_CONFIG[config.target_os]["archs"][config.arch][
            "env"
        ].items():
            if value[1] == "set":
                os.environ[key] = ""


def set_env_var(config):
    clear_env_variables(config)
    if "env" in GLOBAL_CONFIG[config.target_os]:
        for key, value in GLOBAL_CONFIG[config.target_os]["env"].items():
            concatenate_env_variable(key, value[0])
    if "env" in GLOBAL_CONFIG[config.target_os]["archs"][config.arch]:
        for key, value in GLOBAL_CONFIG[config.target_os]["archs"][config.arch][
            "env"
        ].items():
            concatenate_env_variable(key, value[0])


def config_local_env_vars(config, local_config):
    clear_env_variables(config)
    if "env" in local_config[config.target_os]:
        for env, tuple in local_config[config.target_os]["env"].items():
            if not "env" in GLOBAL_CONFIG[config.target_os]:
                GLOBAL_CONFIG[config.target_os]["env"] = {env: tuple}
                return
            if env in GLOBAL_CONFIG[config.target_os]["env"]:
                if tuple[0] not in GLOBAL_CONFIG[config.target_os]["env"][env][0]:
                    GLOBAL_CONFIG[config.target_os]["env"][env][0].append(tuple[0])
            else:
                GLOBAL_CONFIG[config.target_os]["env"][env] = tuple

    if (
        "archs" in local_config[config.target_os]
        and config.arch in local_config[config.target_os]["archs"]
    ):
        if "env" in local_config[config.target_os]["archs"][config.arch]:
            for env, tuple in local_config[config.target_os]["archs"][config.arch][
                "env"
            ].items():
                if not "env" in GLOBAL_CONFIG[config.target_os]["archs"][config.arch]:
                    GLOBAL_CONFIG[config.target_os]["archs"][config.arch]["env"] = {
                        env: tuple
                    }
                    return
                if env in GLOBAL_CONFIG[config.target_os]["archs"][config.arch]["env"]:
                    if (
                        tuple[0]
                        not in GLOBAL_CONFIG[config.target_os]["archs"][config.arch][
                            "env"
                        ][env][0]
                    ):
                        GLOBAL_CONFIG[config.target_os]["archs"][config.arch]["env"][
                            env
                        ][0].append(tuple[0])
                else:
                    GLOBAL_CONFIG[config.target_os]["archs"][config.arch]["env"][
                        env
                    ] = tuple


def check_config(config):
    if config.arch not in GLOBAL_CONFIG[config.target_os]["archs"]:
        raise Exception(
            f"invalid arch '{config.arch}' for '{config.target_os}', expected {str(list(GLOBAL_CONFIG[config.target_os]['archs'].keys()))}"
        )


def create_cli_parser() -> Any:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command")
    subparsers.required = True

    build_parser = subparsers.add_parser("build", help="build a specific os/arch pair")
    build_parser.add_argument("os", type=str, choices=list(GLOBAL_CONFIG.keys()))
    build_parser.add_argument("arch", type=str)
    build_parser.add_argument("--debug", action="store_true", help="Create debug build")

    lipo_parser = subparsers.add_parser(
        "lipo",
        help="create fat multiarchitecture binaries using lipo, and assembly dist/darwin/lib(name)",
    )
    lipo_parser.add_argument("--debug", action="store_true", help="lipo debug build")
    lipo_parser.add_argument(
        "--build",
        action="store_true",
        help="builds all needed archs before executing lipo",
    )

    return parser


def parse_cli():
    return create_cli_parser().parse_args()


def build_target(config, binaries=None, packages=None):
    run_command(["rustup", "default", config.version])
    run_command(["rustup", "target", "add", config.rust_target])

    build_command = [
        "cargo",
        "build",
        "--verbose",
        "--target",
        config.rust_target,
        "--lib",
    ]
    package_build_command = [
        "cargo",
        "build",
        "--verbose",
        "--target",
        config.rust_target,
    ]

    if not config.debug:
        build_command.append("--release")
        package_build_command.append("--release")
    if binaries is not None:
        for binary in binaries:
            build_command += ["--bin", binary]

    run_command(build_command)

    if packages is not None:
        for package in packages:
            package_build_command += ["--package", package]
        run_command(package_build_command)


def build(config, binaries=None, packages=None):
    config.set_rust_target()
    pre_build(config)
    distribution_dir = get_distribution_path(
        config.target_os, config.arch, "", config.debug
    )
    if os.path.isdir(distribution_dir):
        shutil.rmtree(distribution_dir)
    os.makedirs(distribution_dir)
    if binaries is None and packages is None:
        build_target(config)
    else:
        build_target(config, binaries, packages)
        if binaries is not None:
            for binary in binaries:
                if config.target_os == "windows":
                    binary += ".exe"
                # copies executable permissions
                shutil.copy2(
                    get_cargo_path(config.rust_target, binary, config.debug),
                    get_distribution_path(
                        config.target_os, config.arch, binary, config.debug
                    ),
                )
        if packages is not None:
            for package in packages:
                if config.target_os == "windows":
                    package += ".exe"
                # copies executable permissions
                shutil.copy2(
                    get_cargo_path(config.rust_target, package, config.debug),
                    get_distribution_path(
                        config.target_os, config.arch, package, config.debug
                    ),
                )
    shutil.copyfile(
        get_cargo_path(config.rust_target, config.lib_name, config.debug),
        get_distribution_path(
            config.target_os, config.arch, config.lib_name, config.debug
        ),
    )
    post_build(config)


def str_to_func_call(func_string):
    func_array = func_string.split(".")
    func = func_array[-1]
    func_array.pop(-1)
    module = ".".join(func_array)

    return getattr(importlib.import_module(module), func)


def pre_build(config):
    set_env_var(config)
    if "pre_build" in GLOBAL_CONFIG[config.target_os]:
        pre_array = GLOBAL_CONFIG[config.target_os]["pre_build"]
        for function in pre_array:
            func_call = str_to_func_call(function)
            func_call(config)


def post_build(config):
    if "post_build" in GLOBAL_CONFIG[config.target_os]:
        post_array = GLOBAL_CONFIG[config.target_os]["post_build"]
        for function in post_array:
            func_call = str_to_func_call(function)
            func_call(config)


def get_distribution_path(target_os, architecture, path, debug):
    local_dir = DISTRIBUTION_DIR
    if target_os == "macos" or target_os == "ios":
        local_dir = f"{DISTRIBUTION_DIR}/darwin"
    if debug:
        return os.path.normpath(f"{local_dir}/{target_os}/debug/{architecture}/{path}")
    return os.path.normpath(f"{local_dir}/{target_os}/release/{architecture}/{path}")


def get_cargo_path(target, path, debug):
    if debug:
        return os.path.normpath(f"{TARGET_DIR}/{target}/debug/{path}")
    return os.path.normpath(f"{TARGET_DIR}/{target}/release/{path}")


def run_command(command):
    print("|EXECUTE| {}".format(" ".join(command)))
    subprocess.check_call(command)
    print("")


def run_command_with_output(command, hide_output=False):
    print("|EXECUTE| {}".format(" ".join(command)))
    result = subprocess.check_output(command).decode("utf-8")
    if hide_output:
        print("(OUTPUT HIDDEN)\n")
    else:
        print(result)
    return result


def copy_tree_or_file(src, dst):
    try:
        shutil.copytree(
            src,
            dst,
        )
    except NotADirectoryError:
        shutil.copy2(
            src,
            dst,
        )


def remove_tree_or_file(path):
    try:
        shutil.rmtree(path)
    except NotADirectoryError:
        os.remove(path)


@dataclass
class CargoConfig:
    target_os: str
    arch: str
    version: str
    lib_name: str
    debug: bool
    rust_target: str = ""

    def set_rust_target(self):
        self.rust_target = GLOBAL_CONFIG[self.target_os]["archs"][self.arch][
            "rust_target"
        ]
