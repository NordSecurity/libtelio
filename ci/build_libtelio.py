#!/usr/bin/env python3

import os
import shutil
import sys
import subprocess
import urllib.request
import zipfile
import hashlib

NAME = "telio"
PROJECT_ROOT = os.path.normpath(os.path.dirname(os.path.realpath(__file__)) + "/..")
WORKING_DIR = f"{PROJECT_ROOT}/"

os.environ["NAME"] = NAME
os.environ["VERSION"] = "1.64.0"
os.environ["PROJECT_ROOT"] = PROJECT_ROOT
os.environ["WORKING_DIR"] = WORKING_DIR

MOOSE_RELEASE_TAG = os.environ.get("MOOSE_RELEASE_TAG")

# `sys.path` is the equivalent of `PYTHONPATH`, aka module search paths
sys.path += [f"{PROJECT_ROOT}/ci/helper-scripts"]
import rust_build_utils.rust_utils as rutils
from rust_build_utils.rust_utils_config import GLOBAL_CONFIG
import rust_build_utils.darwin_build_utils as dbu
import rust_build_utils.android_build_utils as abu

# Need to normalise name in moose, LLT-1486
MOOSE_MAP = {
    "x86_64": "x86_64",
    "aarch64": "aarch64",
    "i686": "i686",
    "armv7": "armv7_eabi",
}


def finalize_win(config):
    def get_dependency(url, name, dll_name, checksum):
        zip_name = name + ".zip"
        with urllib.request.urlopen(url) as f:
            with open(zip_name, "wb") as w:
                content = f.read()
                m = hashlib.sha256()
                m.update(content)
                assert checksum == m.hexdigest(), f"Wrong checksum of downloaded file: {zip_name}"
                w.write(content)
        with zipfile.ZipFile(zip_name, "r") as zip_ref:
            zip_ref.extractall(".")
        shutil.copyfile(
            name + "/bin/amd64/" + dll_name,
            rutils.get_distribution_path(
                config.target_os, config.arch, dll_name, config.debug
            ),
        )
        shutil.rmtree(name)
        os.remove(zip_name)

    get_dependency(
        "https://www.wintun.net/builds/wintun-0.14.1.zip", "wintun", "wintun.dll",
        "07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51"
    )
    get_dependency(
        "https://download.wireguard.com/wireguard-nt/wireguard-nt-0.10.1.zip",
        "wireguard-nt",
        "wireguard.dll",
        "772c0b1463d8d2212716f43f06f4594d880dea4f735165bd68e388fc41b81605",
    )


def copy_bindings(config):
    if "binding_src" in LIBTELIO_CONFIG[config.target_os]:
        telio_bindings = os.path.normpath(
            os.path.join(
                rutils.PROJECT_ROOT, LIBTELIO_CONFIG[config.target_os]["binding_src"]
            )
        )

        binding_destination = os.path.normpath(
            os.path.join(
                rutils.PROJECT_ROOT,
                LIBTELIO_CONFIG[config.target_os]["binding_dest"],
                os.path.basename(telio_bindings),
            )
        )

        if os.path.exists(binding_destination):
            rutils.remove_tree_or_file(binding_destination)

        rutils.copy_tree_or_file(telio_bindings, binding_destination)


# LOCAL_TEMPLATE_CONFIG = {
#   "target_os": {
#       "binaries" :    [Optional, List], list of additional binaries that you want to compile
#       "packages" :    [Optional, List], list of additional packages that you want to compile
#       "binding_src" : [Optional, String], string with full path to binding source (mandatory with binding_dest)
#       "binding_dest": [Optional, String],  string with full path to binding destination (mandatory with binding_src)
#       "pre_build"   : [Optional, List],  list of project specific functions to call before the build begins (this is called before the GLOBAL pre_build)
#       "post_build"  : [Optional, List<>],  list of project specific functions to call after the build finishes (this is called after the GLOBAL post_build)
#   }
# }

LIBTELIO_CONFIG = {
    "windows": {
        "archs": {
            "x86_64": {
                "env": {
                    "RUSTFLAGS": (
                        f" -L {PROJECT_ROOT}/3rd-party/libmoose/{MOOSE_RELEASE_TAG}/bin/common/windows/{MOOSE_MAP['x86_64']}",
                        "set",
                    )
                }
            },
        },
        "packages": ["tcli", "derpcli", "interderpcli"],
        "binding_src": f"ffi/bindings/windows/csharp",
        "binding_dest": f"dist/windows/",
        "post_build": [finalize_win],
    },
    "android": {
        "archs": {
            "x86_64": {
                "env": {
                    "RUSTFLAGS": (
                        f" -L {PROJECT_ROOT}/3rd-party/libmoose/{MOOSE_RELEASE_TAG}/bin/common/android/{MOOSE_MAP['x86_64']}",
                        "set",
                    )
                },
            },
            "aarch64": {
                "env": {
                    "RUSTFLAGS": (
                        f" -L {PROJECT_ROOT}/3rd-party/libmoose/{MOOSE_RELEASE_TAG}/bin/common/android/{MOOSE_MAP['aarch64']}",
                        "set",
                    )
                }
            },
            "i686": {
                "env": {
                    "RUSTFLAGS": (
                        f" -L {PROJECT_ROOT}/3rd-party/libmoose/{MOOSE_RELEASE_TAG}/bin/common/android/{MOOSE_MAP['i686']}",
                        "set",
                    )
                }
            },
            "armv7": {
                "env": {
                    "RUSTFLAGS": (
                        f" -L {PROJECT_ROOT}/3rd-party/libmoose/{MOOSE_RELEASE_TAG}/bin/common/android/{MOOSE_MAP['armv7']}",
                        "set",
                    )
                }
            },
        },
        "env": {
            "RUSTFLAGS": (
                [f" -C debuginfo=2"],
                "set",
            )
        },
        "binding_src": f"ffi/bindings/android/java",
        "binding_dest": f"dist/android/",
    },
    "linux": {
        "packages": ["tcli", "derpcli", "interderpcli"],
        "env": {
            "RUSTFLAGS": ([" -C debuginfo=2 "], "set"),
        },
    },
    "macos": {
        "packages": ["tcli"],
        "binding_src": f"ffi/bindings/telio.h",
        "binding_dest": f"dist/darwin/",
    },
}


def main():
    parser = rutils.create_cli_parser()
    build_parser = parser._subparsers._group_actions[0].choices["build"]
    build_parser.add_argument("--moose", action="store_true", help="Use libmoose")
    args = parser.parse_args()

    if args.command == "build":
        exec_build(args)
    elif args.command == "lipo":
        exec_lipo(args)
    else:
        assert False, f"command '{args.command}' not supported"


def exec_build(args):
    config = rutils.CargoConfig(
        args.os,
        args.arch,
        os.getenv("VERSION"),
        GLOBAL_CONFIG[args.os]["lib_name"],
        args.debug,
    )
    rutils.check_config(config)
    call_build(config)


def create_debug_symbols(config):
    if config.debug:
        return

    if config.target_os != "android" and config.target_os != "linux":
        return

    dist_dir = rutils.get_distribution_path(
        config.target_os, config.arch, "", config.debug
    )

    def _create_debug_symbol(path: str, strip_bin: str = "strip"):
        create_debug_file = [
            f"{strip_bin}",
            "--only-keep-debug",
            f"{path}",
            "-o",
            f"{path}.debug",
        ]
        remove_debug_from_original = [
            f"{strip_bin}",
            "--strip-debug",
            f"{path}",
            "-o",
            f"{path}",
        ]
        set_read_only = ["chmod", "0444", f"{path}.debug"]
        subprocess.check_call(create_debug_file, stderr=subprocess.DEVNULL)
        subprocess.check_call(remove_debug_from_original)
        subprocess.check_call(set_read_only)

    lib_name = GLOBAL_CONFIG[config.target_os]["lib_name"]

    if config.target_os == "linux":
        _create_debug_symbol(f"{dist_dir}/{lib_name}")
    elif config.target_os == "android":
        strip = f"{abu.TOOLCHAIN}/{abu.NDK_MAP[config.arch]}/bin/strip"
        renamed_arch = GLOBAL_CONFIG[config.target_os]["archs"][config.arch]["dist"]
        dist_dir = rutils.get_distribution_path(
            config.target_os, config.arch, "../unstripped", config.debug
        )
        _create_debug_symbol(f"{dist_dir}/{renamed_arch}/{lib_name}", strip_bin=strip)


def call_build(config):
    if not config.target_os in LIBTELIO_CONFIG:
        rutils.build(config)
        return

    rutils.config_local_env_vars(config, LIBTELIO_CONFIG)

    is_binaries = "binaries" in LIBTELIO_CONFIG[config.target_os]
    is_packages = "packages" in LIBTELIO_CONFIG[config.target_os]

    rutils.build(
        config,
        binaries=LIBTELIO_CONFIG[config.target_os]["binaries"] if is_binaries else None,
        packages=LIBTELIO_CONFIG[config.target_os]["packages"] if is_packages else None,
    )

    copy_bindings(config)
    create_debug_symbols(config)

    if "post_build" in LIBTELIO_CONFIG[config.target_os]:
        for post in LIBTELIO_CONFIG[config.target_os]["post_build"]:
            post(config)


def exec_lipo(args):
    if args.build:
        for target_os in rutils.LIPO_TARGET_OSES:
            for arch in GLOBAL_CONFIG[target_os]["archs"].keys():
                config = rutils.CargoConfig(
                    target_os,
                    arch,
                    os.getenv("VERSION"),
                    GLOBAL_CONFIG[target_os]["lib_name"],
                    args.debug,
                )
                call_build(config)

    for target_os in rutils.LIPO_TARGET_OSES:
        if target_os not in LIBTELIO_CONFIG:
            continue
        is_binaries = "binaries" in LIBTELIO_CONFIG[target_os]
        is_packages = "packages" in LIBTELIO_CONFIG[target_os]
        dbu.lipo(
            args.debug,
            target_os,
            binaries=LIBTELIO_CONFIG[target_os]["binaries"] if is_binaries else None,
            packages=LIBTELIO_CONFIG[target_os]["packages"] if is_packages else None,
        )


if __name__ == "__main__":
    main()
