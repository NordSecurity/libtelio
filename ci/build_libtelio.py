#!/usr/bin/env python3

import os
import sys
import subprocess
import moose_utils
import shutil
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
from env import LIBTELIO_ENV_UNIFFI_GENERATORS_TAG

# Need to normalise name in moose, LLT-1486
MOOSE_MAP = {
    "x86_64": "x86_64",
    "aarch64": "aarch64",
    "i686": "i686",
    "armv5": "armv5_eabi",
    "armv7": "armv7_eabi",
    "armv7hf": "armv7_eabihf",
}

PROJECT_CONFIG = rutils.Project(
    rust_version="1.77.2",
    root_dir=PROJECT_ROOT,
    working_dir=WORKING_DIR,
)


def post_copy_libsqlite3_binary_to_dist(config, args):
    if args.moose:
        sqlite_path = f"{PROJECT_ROOT}/3rd-party/libmoose/{LIBTELIO_ENV_MOOSE_RELEASE_TAG}/bin/common/linux/{MOOSE_MAP[config.arch]}/libsqlite3.so"
        shutil.copyfile(
            sqlite_path,
            PROJECT_CONFIG.get_distribution_path(
                config.target_os, config.arch, "libsqlite3.so", config.debug
            ),
        )


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
            "aarch64": {
                "env": {
                    "RUSTFLAGS": (
                        f" -L {PROJECT_ROOT}/3rd-party/libmoose/{LIBTELIO_ENV_MOOSE_RELEASE_TAG}/bin/common/windows/{MOOSE_MAP['aarch64']}",
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
    },
    "linux": {
        "archs": {
            "x86_64": {
                "strip_path": "/usr/bin/strip",
                "env": {
                    "RUSTFLAGS": (
                        f" -L {PROJECT_ROOT}/3rd-party/libmoose/{LIBTELIO_ENV_MOOSE_RELEASE_TAG}/bin/common/linux/{MOOSE_MAP['x86_64']}",
                        "set",
                    )
                },
            },
            "aarch64": {
                "strip_path": "/usr/aarch64-linux-gnu/bin/strip",
                "env": {
                    "RUSTFLAGS": (
                        f" -L {PROJECT_ROOT}/3rd-party/libmoose/{LIBTELIO_ENV_MOOSE_RELEASE_TAG}/bin/common/linux/{MOOSE_MAP['aarch64']}",
                        "set",
                    )
                },
            },
            "arm64": {
                "strip_path": "/usr/aarch64-linux-gnu/bin/strip",
                "env": {
                    "RUSTFLAGS": (
                        f" -L {PROJECT_ROOT}/3rd-party/libmoose/{LIBTELIO_ENV_MOOSE_RELEASE_TAG}/bin/common/linux/{MOOSE_MAP['aarch64']}",
                        "set",
                    )
                },
            },
            "i686": {
                "strip_path": "/usr/i686-linux-gnu/bin/strip",
                "env": {
                    "RUSTFLAGS": (
                        f" -L {PROJECT_ROOT}/3rd-party/libmoose/{LIBTELIO_ENV_MOOSE_RELEASE_TAG}/bin/common/linux/{MOOSE_MAP['i686']}",
                        "set",
                    )
                },
            },
            "armv7hf": {
                "strip_path": "/usr/arm-linux-gnueabihf/bin/strip",
                "env": {
                    "RUSTFLAGS": (
                        f" -L {PROJECT_ROOT}/3rd-party/libmoose/{LIBTELIO_ENV_MOOSE_RELEASE_TAG}/bin/common/linux/{MOOSE_MAP['armv7hf']}",
                        "set",
                    )
                },
            },
            "armv5": {
                "strip_path": "/usr/arm-linux-gnueabi/bin/strip",
                "env": {
                    "RUSTFLAGS": (
                        f" -L {PROJECT_ROOT}/3rd-party/libmoose/{LIBTELIO_ENV_MOOSE_RELEASE_TAG}/bin/common/linux/{MOOSE_MAP['armv5']}",
                        "set",
                    )
                },
            },
        },
        "post_build": [post_copy_libsqlite3_binary_to_dist],
        "env": {
            "RUSTFLAGS": ([" -C debuginfo=2 "], "set"),
        },
        "packages": {
            "tcli": {"tcli": "tcli"},
            "derpcli": {"derpcli": "derpcli"},
            "interderpcli": {"interderpcli": "interderpcli"},
            NAME: {f"lib{NAME}": f"lib{NAME}.so"},
        },
    },
    "macos": {
        "packages": {
            "tcli": {"tcli": "tcli"},
            NAME: {f"lib{NAME}": f"lib{NAME}.dylib"},
        }
    },
    "ios": {
        "packages": {
            NAME: {f"lib{NAME}": f"lib{NAME}.dylib"},
        },
    },
    "tvos": {
        "packages": {
            NAME: {f"lib{NAME}": f"lib{NAME}.dylib"},
        },
    },
}


def main() -> None:
    parser = rutils.create_cli_parser()
    build_parser = parser._subparsers._group_actions[0].choices["build"]
    build_parser.add_argument("--moose", action="store_true", help="Use libmoose")
    build_parser.add_argument(
        "--msvc", action="store_true", help="Use MSVC toolchain for Windows build"
    )

    args = parser.parse_args()

    if args.command == "build":
        exec_build(args)
    elif args.command == "bindings":
        rutils.generate_uniffi_bindings(
            PROJECT_CONFIG,
            LIBTELIO_ENV_UNIFFI_GENERATORS_TAG,
            ["python", "cs", "go", "swift", "kotlin"],
            "src/libtelio.udl",
        )
    elif args.command == "lipo":
        exec_lipo(args)
    elif args.command == "aar":
        abu.generate_aar(PROJECT_CONFIG, args)
    elif args.command == "xcframework":
        headers = {
            Path("libtelio/module.modulemap"): Path(
                os.path.join(PROJECT_CONFIG.get_bindings_dir(), "telioFFI.modulemap")
            ),
            Path("libtelio/telioFFI.h"): Path(
                os.path.join(PROJECT_CONFIG.get_bindings_dir(), "telioFFI.h")
            ),
        }
        dbu.create_xcframework(
            PROJECT_CONFIG, args.debug, "libtelioFFI", headers, "libtelio.dylib"
        )
    elif args.command == "build-ios-simulator-stubs":
        dbu.build_stub_ios_simulator_libraries(
            PROJECT_CONFIG,
            args.debug,
            args.header
            or Path(os.path.join(PROJECT_CONFIG.get_bindings_dir(), "telioFFI.h")),
            "libtelio.dylib",
        )
    elif args.command == "build-tvos-simulator-stubs":
        dbu.build_stub_tvos_simulator_libraries(
            PROJECT_CONFIG,
            args.debug,
            args.header
            or Path(os.path.join(PROJECT_CONFIG.get_bindings_dir(), "telioFFI.h")),
            "libtelio.dylib",
        )
    else:
        assert False, f"command '{args.command}' not supported"


def exec_build(args):
    if args.moose:
        if args.os in ["linux", "windows", "android"]:
            sys.path.append(f"{PROJECT_ROOT}/ci")
            moose_utils.fetch_moose_dependencies(args.os, MOOSE_MAP[args.arch])

        moose_utils.set_cargo_dependencies()
        # TODO: remove when we get rid of sm crate (LLT-4929)
        # We are using an outdated library in telio-traversal called sm
        # It uses some old versions of quote, proc-macro2 and syn.
        # When the moose dependency is injected by the build script it tries to
        # use these old versions of quote, proc-macro2 and syn. A cargo update
        # should fix it for now, but it's prone to errors, so we should find an
        # alternative solution for the sm library.
        rutils.run_command(["cargo", "update", "-p", "quote@0.6.13"])
        rutils.run_command(["cargo", "update", "-p", "proc-macro2@0.4.30"])
        rutils.run_command(["cargo", "update", "-p", "syn@0.15.44"])
    else:
        moose_utils.unset_cargo_dependencies()

    if args.os == "windows":
        if args.msvc:
            # Windows MSVC toolchain
            if not "env" in GLOBAL_CONFIG["windows"]:
                GLOBAL_CONFIG["windows"]["env"] = {"RUSTFLAGS": ()}

            if not "RUSTFLAGS" in GLOBAL_CONFIG["windows"]["env"]:
                GLOBAL_CONFIG["windows"]["env"]["RUSTFLAGS"] = ()

            GLOBAL_CONFIG["windows"]["env"]["RUSTFLAGS"] += (
                [" -C target-feature=-crt-static "],
                "set",
            )
            if args.moose:
                moose_utils.create_msvc_import_library(args.arch)
        else:
            # Windows GNU toolchain
            GLOBAL_CONFIG["windows"]["archs"][args.arch]["rust_target"] = (
                args.arch + "-pc-windows-gnu"
            )

    config = rutils.CargoConfig(
        args.os,
        args.arch,
        args.debug,
    )
    rutils.check_config(config)
    call_build(config, args)


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
    binaries = [
        bin for bin in LIBTELIO_CONFIG["linux"]["packages"].keys() if bin != NAME
    ]
    for binary in binaries:
        _strip_debug_symbols(f"{dist_dir}/{binary}", strip_bin=strip)


def call_build(config, args):
    rutils.config_local_env_vars(config, LIBTELIO_CONFIG)

    rutils.cargo_build(
        PROJECT_CONFIG,
        config,
        LIBTELIO_CONFIG[config.target_os].get("packages", None),
        LIBTELIO_CONFIG[config.target_os].get("build_args", None),
    )

    create_debug_symbols(config)
    strip_binaries(config)
    if "post_build" in LIBTELIO_CONFIG[config.target_os]:
        for post in LIBTELIO_CONFIG[config.target_os]["post_build"]:
            post(config, args)


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
