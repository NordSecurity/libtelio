import os
import re
import subprocess

from env import LIBTELIO_ENV_MOOSE_RELEASE_TAG
from utils import run_with_retry

PROJECT_ROOT = os.path.normpath(os.path.dirname(os.path.realpath(__file__)) + "/..")


def _output_dir(target_os: str, arch: str) -> str:
    return os.path.join(
        PROJECT_ROOT,
        "3rd-party",
        "libmoose",
        LIBTELIO_ENV_MOOSE_RELEASE_TAG,
        "bin",
        "common",
        target_os,
        arch,
    )


def _download_moose_file(target_os: str, arch: str, file_name: str):
    MOOSE_PROJECT_ID = 5644

    output_path = os.path.join(_output_dir(target_os, arch), file_name)
    if os.path.isfile(output_path):
        return

    print(f"Moose utils: Downloading {target_os}/{arch}/{file_name}")

    if not os.path.isdir(os.path.dirname(output_path)):
        os.makedirs(os.path.dirname(output_path))

    nexus_credentials = os.environ.get("LIBTELIO_ENV_SEC_NEXUS_CREDENTIALS", None)
    nexus_url = os.environ.get("LIBTELIO_ENV_SEC_NEXUS_URL", None)

    if nexus_credentials is None:
        raise ValueError("LIBTELIO_ENV_SEC_NEXUS_CREDENTIALS not set")

    if nexus_url is None:
        raise ValueError("LIBTELIO_ENV_SEC_NEXUS_URL not set")

    url = f"{nexus_url}/repository/ll-gitlab-release/{MOOSE_PROJECT_ID}/{LIBTELIO_ENV_MOOSE_RELEASE_TAG}/bin/common/{target_os}/{arch}/{file_name}"

    run_with_retry(
        lambda: subprocess.run(
            ["curl", "-f", "-u", nexus_credentials, url, "-o", output_path],
            capture_output=True,
            check=True,
        ),
        exceptions=(subprocess.CalledProcessError,),
    )


def fetch_moose_dependencies(target_os: str, arch: str):
    if target_os == "windows":
        _download_moose_file(target_os, arch, "sqlite3.dll")
    else:
        _download_moose_file(target_os, arch, "libsqlite3.so")


def create_msvc_import_library(arch: str):
    def execute_dumpbin(file_path: str) -> list[str]:
        output = subprocess.check_output(["dumpbin", "/EXPORTS", file_path])
        output_lines = output.decode().split("\n")[19:]
        for i, line in enumerate(output_lines):
            if not line.strip():
                output_lines = output_lines[:i]
                break
        return [line.split()[-1] for line in output_lines]

    def write_exports(exports: list[str], file_path: str):
        with open(file_path, "w") as f:
            f.write("LIBRARY SQLITE3\n")
            f.write("EXPORTS\n")
            for export in exports:
                f.write(f"    {export}\n")

    def create_lib(def_path: str, lib_path: str, arch: str):
        arch_upd = ""
        if arch == "x86_64":
            arch_upd = "X64"
        elif arch == "aarch64":
            arch_upd = "ARM64"
        else:
            print(f"Unsupported architecture: {arch}")

        subprocess.check_call(
            ["lib", "/DEF:" + def_path, "/OUT:" + lib_path, "/MACHINE:" + arch_upd]
        )

    output_dir = _output_dir("windows", arch)
    dll_path = os.path.join(output_dir, "sqlite3.dll")
    def_path = os.path.join(output_dir, "sqlite3.def")
    lib_path = os.path.join(output_dir, "sqlite3.lib")

    exports = execute_dumpbin(dll_path)
    write_exports(exports, def_path)
    create_lib(def_path, lib_path, arch)


def _write_file(file_name, contents):
    with open(file_name, "w") as cargoFile:
        cargoFile.write(contents)


def set_cargo_dependencies():
    libtelio_env_sec_gitlab_repository = os.environ.get(
        "LIBTELIO_ENV_SEC_GITLAB_REPOSITORY", None
    )

    if libtelio_env_sec_gitlab_repository is None:
        raise ValueError("LIBTELIO_ENV_SEC_GITLAB_REPOSITORY not set.")

    MOOSELIBTELIOAPP_DEP = (
        r"\nmooselibtelioapp = { "
        f'git = "https://{libtelio_env_sec_gitlab_repository}/nord-projects/nordvpn/infra/llt/moose/moose-events",'
        f' tag = "{LIBTELIO_ENV_MOOSE_RELEASE_TAG}" }}'
    )

    # add telio-lana/moose to root Cargo.toml
    with open(f"{PROJECT_ROOT}/Cargo.toml", "r") as cargoFile:
        cargo_contents = cargoFile.read()
        match_lana = re.search(r"telio-lana.*}", cargo_contents)
        if match_lana:
            if "features" not in match_lana.group(0):
                replaced_moose = re.sub(
                    r"( \})", r', features = ["moose"]\1', match_lana.group(0)
                )
                cargo_contents = cargo_contents.replace(
                    match_lana.group(0), replaced_moose
                )
                _write_file(f"{PROJECT_ROOT}/Cargo.toml", cargo_contents)
            elif '"moose"' not in match_lana.group(0):
                replaced_moose = re.sub(
                    r"(features.*\[)(.*\])", r'\1"moose", \2', match_lana.group(0)
                )
                cargo_contents = cargo_contents.replace(
                    match_lana.group(0), replaced_moose
                )
                _write_file("./Cargo.toml", cargo_contents)

    # add mooselibtelioapp and moose feature dependency to telio-lana/Cargo.toml
    with open(f"{PROJECT_ROOT}/crates/telio-lana/Cargo.toml", "r") as lana_cargo_file:
        lana_cargo_contents = lana_cargo_file.read()

        if "moose = []" not in lana_cargo_contents:
            match_feature = re.search(r"\[features\]", lana_cargo_contents)
            if match_feature:
                lana_cargo_contents += "moose = []\n"
            else:
                lana_cargo_contents += "\n[features]\nmoose = []\n"

        if "mooselibtelioapp" not in lana_cargo_contents:
            match_dependencies = re.search(r"\[dependencies\]", lana_cargo_contents)
            replaced_dependencies = re.sub(
                r"$", MOOSELIBTELIOAPP_DEP, match_dependencies.group(0)
            )
            lana_cargo_contents = lana_cargo_contents.replace(
                match_dependencies.group(0), replaced_dependencies
            )
        _write_file(f"{PROJECT_ROOT}/crates/telio-lana/Cargo.toml", lana_cargo_contents)


def unset_cargo_dependencies():
    # remove telio-lana/moose feature from root Cargo.toml
    with open(f"{PROJECT_ROOT}/Cargo.toml", "r") as cargoFile:
        cargo_contents = cargoFile.read()
        match_lana = re.search(r'telio-lana.*"moose"', cargo_contents)
        if match_lana:
            replaced_moose = re.sub(
                r'(telio-lana.*)"moose"(, )*(.*})', r"\1\3", cargo_contents
            )
            empty_features = re.search(
                r'(telio-lana.*features.*)\[[^"]*\]', replaced_moose
            )
            if empty_features:
                replaced_moose = re.sub(
                    r'(telio-lana.*)(,\sfeatures.*)\[[^"]*\]', r"\1", replaced_moose
                )
            _write_file(f"{PROJECT_ROOT}/Cargo.toml", replaced_moose)

    # remove mooselibtelioapp dependency from telio-lana/Cargo.toml
    with open(f"{PROJECT_ROOT}/crates/telio-lana/Cargo.toml", "r") as lana_cargo_file:
        lana_cargo_contents = lana_cargo_file.read()
        if "mooselibtelioapp" in lana_cargo_contents:
            lana_cargo_contents = re.sub(
                r"\nmooselibtelioapp.*\n", "\n", lana_cargo_contents
            )
            _write_file(
                f"{PROJECT_ROOT}/crates/telio-lana/Cargo.toml", lana_cargo_contents
            )
