#!/usr/bin/env python3

import os
import shutil
import sys
import subprocess
import urllib.request
import zipfile
import moose_utils
from pathlib import Path

NAME = "telio"
PROJECT_ROOT = os.path.normpath(os.path.dirname(os.path.realpath(__file__)) + "/..")
WORKING_DIR = f"{PROJECT_ROOT}"

# `sys.path` is the equivalent of `PYTHONPATH`, aka module search paths
sys.path += [f"{PROJECT_ROOT}/3rd-party/rust_build_utils"]

import rust_build_utils.rust_utils as rutils
from rust_build_utils.rust_utils_config import GLOBAL_CONFIG
import rust_build_utils.darwin_build_utils as dbu
import rust_build_utils.android_build_utils as abu
from env import LIBTELIO_ENV_MOOSE_RELEASE_TAG

# Need to normalise name in moose, LLT-1486
MOOSE_MAP = {
    "x86_64": "x86_64",
    "aarch64": "aarch64",
    "i686": "i686",
    "armv7": "armv7_eabi",
}

PROJECT_CONFIG = rutils.Project(
    rust_version="1.72.1",
    root_dir=PROJECT_ROOT,
    working_dir=WORKING_DIR,
)


def finalize_win(config, moose):
    def get_dependency(url, name, dll_name):
        zip_name = name + ".zip"
        with urllib.request.urlopen(url) as f:
            with open(zip_name, "wb") as w:
                w.write(f.read())
        with zipfile.ZipFile(zip_name, "r") as zip_ref:
            zip_ref.extractall(".")
        shutil.copyfile(
            name + "/bin/amd64/" + dll_name,
            PROJECT_CONFIG.get_distribution_path(
                config.target_os, config.arch, dll_name, config.debug
            ),
        )
        shutil.rmtree(name)
        os.remove(zip_name)

    get_dependency(
        "https://www.wintun.net/builds/wintun-0.14.1.zip", "wintun", "wintun.dll"
    )
    get_dependency(
        "https://download.wireguard.com/wireguard-nt/wireguard-nt-0.10.1.zip",
        "wireguard-nt",
        "wireguard.dll",
    )

    if moose:
        sqlite_path = f"{PROJECT_ROOT}/3rd-party/libmoose/{LIBTELIO_ENV_MOOSE_RELEASE_TAG}/bin/common/windows/{config.arch}/sqlite3.dll"
        shutil.copyfile(
            sqlite_path,
            PROJECT_CONFIG.get_distribution_path(
                config.target_os, config.arch, "sqlite3.dll", config.debug
            ),
        )


def copy_bindings(config):
    if "binding_src" in LIBTELIO_CONFIG[config.target_os]:
        telio_bindings = f"{PROJECT_CONFIG.root_dir}/{LIBTELIO_CONFIG[config.target_os]['binding_src']}"
        binding_destination = (
            f"{PROJECT_CONFIG.root_dir}/{LIBTELIO_CONFIG[config.target_os]['binding_dest']}"
            + telio_bindings.split("/")[-1]
        )

        if os.path.exists(binding_destination):
            rutils.remove_tree_or_file(binding_destination)

        rutils.copy_tree_or_file(telio_bindings, binding_destination)


"""
This local config is highly customizable as every project can have a different
local config depending on their needs.

Here are some generic attributes that you may wish to use in several projects:
      "build_args"  : [Optional, List<str>]:
          List of global arguments to be passed for all packages to be built.
          If you need per-package arguments, you can invoke the build() method
          for each package with different extra_args arguments.

      "packages"    : [Dict<str, Dict<str, str>>]:
          Dictionary of packages to build and binaries to distribute.

          The keys are package names, while the values are dictionaries,
          with binary names as keys and their file names as values.

      "pre_build"   : [Optional, List<function>]:
          list of project specific functions to call before the build begins
          (this is called before the GLOBAL pre_build)

      "post_build"  : [Optional, List<function>]:
          list of project specific functions to call after the build finishes
          (this is called after the GLOBAL post_build)

If you would like to have local environment variables, here is a way to do it for the needed OS:
      "env"         : [Optional, Dictionary]:
          dictionary where the key is the environment variable and the value is
          a tuple of (String, String) where member[0] is the value of the flag
          and [1] is either "set" or "append". Member[1] will only be used if
          no such variable already exists in the GLOBAL_CONFIG
          in which case, "set" means that the variable will be cleared before setting it

And another way where you need an environment variable for a specific ARCH build of an OS
      "archs" : Dictionary for multiple arches that are built for an OS
          "$ARCH": Dictionary for any specific configuration to be done for that arch
              "env" : Same structure as the OS specific dictionary

The environment example is given here as well as in the GLOBAL_CONFIG,
you can have both arch specific and OS specific variables at the same time
"""

LIBTELIO_CONFIG = {
    "windows": {
        "archs": {
            "x86_64": {
                "env": {
                    "RUSTFLAGS": (
                        f" -L {PROJECT_ROOT}/3rd-party/libmoose/{LIBTELIO_ENV_MOOSE_RELEASE_TAG}/bin/common/windows/{MOOSE_MAP['x86_64']}",
                        "set",
                    )
                }
            },
        },
        "packages": {
            "tcli": {"tcli": "tcli.exe"},
            "derpcli": {"derpcli": "derpcli.exe"},
            "interderpcli": {"interderpcli": "interderpcli.exe"},
            NAME: {NAME: f"{NAME}.dll"},
        },
        "binding_src": f"ffi/bindings/windows/csharp",
        "binding_dest": f"dist/windows/",
    },
    "android": {
        "archs": {
            "x86_64": {
                "env": {
                    "RUSTFLAGS": (
                        f" -L {PROJECT_ROOT}/3rd-party/libmoose/{LIBTELIO_ENV_MOOSE_RELEASE_TAG}/bin/common/android/{MOOSE_MAP['x86_64']}",
                        "set",
                    )
                },
            },
            "aarch64": {
                "env": {
                    "RUSTFLAGS": (
                        f" -L {PROJECT_ROOT}/3rd-party/libmoose/{LIBTELIO_ENV_MOOSE_RELEASE_TAG}/bin/common/android/{MOOSE_MAP['aarch64']}",
                        "set",
                    )
                }
            },
            "i686": {
                "env": {
                    "RUSTFLAGS": (
                        f" -L {PROJECT_ROOT}/3rd-party/libmoose/{LIBTELIO_ENV_MOOSE_RELEASE_TAG}/bin/common/android/{MOOSE_MAP['i686']}",
                        "set",
                    )
                }
            },
            "armv7": {
                "env": {
                    "RUSTFLAGS": (
                        f" -L {PROJECT_ROOT}/3rd-party/libmoose/{LIBTELIO_ENV_MOOSE_RELEASE_TAG}/bin/common/android/{MOOSE_MAP['armv7']}",
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
        "packages": {
            NAME: {f"lib{NAME}": f"lib{NAME}.so"},
        },
        "binding_src": f"ffi/bindings/android/java",
        "binding_dest": f"dist/android/",
    },
    "linux": {
        "archs": {
            "x86_64": {
                "strip_path": "/usr/bin/strip"
            },
            "aarch64": {
                "strip_path": "/usr/aarch64-linux-gnu/bin/strip"
            },
            "arm64": {
                "strip_path": "/usr/aarch64-linux-gnu/bin/strip"
            },
            "i686": {
                "strip_path": "/usr/i686-linux-gnu/bin/strip"
            },
            "armv7": {
                "strip_path": "/usr/arm-linux-gnueabihf/bin/strip"
            },
            "armv5": {
                "strip_path": "/usr/arm-linux-gnueabi/bin/strip"
            }
        },
        "env": {
            "RUSTFLAGS": ([" -C debuginfo=2 "], "set"),
        },
        "packages": {
            "tcli": {"tcli": "tcli"},
            "derpcli": {"derpcli": "derpcli"},
            "interderpcli": {"interderpcli": "interderpcli"},
            NAME: {f"lib{NAME}": f"lib{NAME}.a"},
        },
    },
    "macos": {
        "packages": {
            "tcli": {"tcli": "tcli"},
            NAME: {f"lib{NAME}": f"lib{NAME}.a"},
        },
        "binding_src": f"ffi/bindings/telio.h",
        "binding_dest": f"dist/darwin/",
    },
    "ios": {
        "packages": {
            NAME: {f"lib{NAME}": f"lib{NAME}.a"},
        },
    },
    "tvos": {
        "packages": {
            NAME: {f"lib{NAME}": f"lib{NAME}.a"},
        },
    },
}


def main() -> None:
    parser = rutils.create_cli_parser()
    build_parser = parser._subparsers._group_actions[0].choices["build"]
    build_parser.add_argument("--moose", action="store_true", help="Use libmoose")
    build_parser.add_argument("--msvc", action="store_true", help="Use MSVC toolchain for Windows build")

    args = parser.parse_args()

    if args.command == "build":
        exec_build(args)
    elif args.command == "lipo":
        exec_lipo(args)
    elif args.command == "aar":
        abu.generate_aar(PROJECT_CONFIG, args)
    elif args.command == "xcframework":
        headers = {
            Path("libtelio/module.modulemap"): PROJECT_CONFIG.get_root_dir()
            / "contrib/darwin/module.modulemap",
            Path("libtelio/telio.h"): PROJECT_CONFIG.get_root_dir()
            / "ffi/bindings/telio.h",
        }
        dbu.create_xcframework(
            PROJECT_CONFIG, args.debug, "libtelioFFI", headers, "libtelio.a"
        )
    elif args.command == "build-ios-simulator-stubs":
        dbu.build_stub_ios_simulator_libraries(
            PROJECT_CONFIG,
            args.debug,
            args.header or PROJECT_CONFIG.get_root_dir() / "ffi/bindings/telio.h",
            "libtelio.a",
        )
    elif args.command == "build-tvos-simulator-stubs":
        dbu.build_stub_tvos_simulator_libraries(
            PROJECT_CONFIG,
            args.debug,
            args.header or PROJECT_CONFIG.get_root_dir() / "ffi/bindings/telio.h",
            "libtelio.a",
        )
    else:
        assert False, f"command '{args.command}' not supported"


def exec_build(args):
    if args.moose:
        if args.os in ["windows", "android"]:
            sys.path.append(f"{PROJECT_ROOT}/ci")
            moose_utils.fetch_moose_dependencies(args.os, MOOSE_MAP[args.arch])
        moose_utils.set_cargo_dependencies()
    else:
        moose_utils.unset_cargo_dependencies()

    if args.msvc:
        GLOBAL_CONFIG["windows"]["archs"]["x86_64"]["rust_target"] = "x86_64-pc-windows-msvc"
        GLOBAL_CONFIG["windows"]["env"]["RUSTFLAGS"] = ([" -C target-feature=-crt-static "], "set")
        if args.moose:
            moose_utils.create_msvc_import_library()

    config = rutils.CargoConfig(
        args.os,
        args.arch,
        args.debug,
    )
    rutils.check_config(config)
    call_build(config)

    if args.os == "windows":
        finalize_win(config, args.moose)


def create_debug_symbols(config):
    if config.debug:
        return

    if config.target_os != "android" and config.target_os != "linux":
        return

    dist_dir = PROJECT_CONFIG.get_distribution_path(
        config.target_os, config.arch, "", config.debug
    )

    def _create_debug_symbol(path: str, strip_bin: str):
        if not os.path.isfile(strip_bin):
            # fallback to default strip
            strip_bin = "strip"
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

    lib_name = LIBTELIO_CONFIG[config.target_os]["packages"][NAME][
        f"lib{NAME}" if config.target_os != "windows" else NAME
    ]

    if config.target_os == "linux":
        strip = LIBTELIO_CONFIG["linux"]["archs"][config.arch]["strip_path"]
        _create_debug_symbol(f"{dist_dir}/{lib_name}", strip_bin=strip)
    elif config.target_os == "android":
        strip = f"{abu.TOOLCHAIN}/bin/llvm-strip"
        renamed_arch = GLOBAL_CONFIG[config.target_os]["archs"][config.arch]["dist"]
        dist_dir = PROJECT_CONFIG.get_distribution_path(
            config.target_os, config.arch, "../unstripped", config.debug
        )
        _create_debug_symbol(f"{dist_dir}/{renamed_arch}/{lib_name}", strip_bin=strip)

def strip_binaries(config):
    if config.debug or config.target_os != "linux":
        return

    dist_dir = PROJECT_CONFIG.get_distribution_path(
        config.target_os, config.arch, "", config.debug
    )

    def _strip_debug_symbols(path: str, strip_bin: str):
        if not os.path.isfile(strip_bin):
            # fallback to default strip
            strip_bin = "strip"
        strip_debug_symbols = [
            f"{strip_bin}",
            "--strip-debug",
            f"{path}",
            "-o",
            f"{path}",
        ]
        subprocess.check_call(strip_debug_symbols)

    strip = LIBTELIO_CONFIG["linux"]["archs"][config.arch]["strip_path"]
    binaries = [bin for bin in LIBTELIO_CONFIG["linux"]["packages"].keys() if bin != NAME]
    for binary in binaries:
        _strip_debug_symbols(f"{dist_dir}/{binary}", strip_bin=strip)

def call_build(config):
    rutils.config_local_env_vars(config, LIBTELIO_CONFIG)

    rutils.cargo_build(
        PROJECT_CONFIG,
        config,
        LIBTELIO_CONFIG[config.target_os].get("packages", None),
        LIBTELIO_CONFIG[config.target_os].get("build_args", None),
    )

    copy_bindings(config)
    create_debug_symbols(config)
    strip_binaries(config)

    if "post_build" in LIBTELIO_CONFIG[config.target_os]:
        for post in LIBTELIO_CONFIG[config.target_os]["post_build"]:
            post(config)


def darwin_build_all(debug: bool) -> None:
    for target_os in rutils.LIPO_TARGET_OSES:
        for arch in GLOBAL_CONFIG[target_os]["archs"].keys():
            if target_os in LIBTELIO_CONFIG:
                config = rutils.CargoConfig(
                    target_os,
                    arch,
                    debug,
                )

                call_build(config)


def exec_lipo(args):
    if args.build:
        darwin_build_all(args.debug)

    for target_os in rutils.LIPO_TARGET_OSES:
        dbu.lipo(
            PROJECT_CONFIG,
            args.debug,
            target_os,
            LIBTELIO_CONFIG[target_os]["packages"],
        )


if __name__ == "__main__":
    main()
