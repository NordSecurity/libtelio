import re
import os
import shutil
import rust_build_utils.rust_utils as rutils
from rust_build_utils.rust_utils_config import GLOBAL_CONFIG


def assert_version(config):  # library, settings
    library = rutils.get_cargo_path(config.rust_target, config.lib_name, config.debug)
    deployment_assert = GLOBAL_CONFIG[config.target_os]["archs"][config.arch][
        "deployment_assert"
    ]
    command = deployment_assert[0]
    minimum_os = deployment_assert[1]

    load_commands = rutils.run_command_with_output(
        ["otool", "-l", library], hide_output=True
    )
    regex = re.compile(rf"{command} (\d+.\d+)")
    matches = re.findall(regex, load_commands)
    assert matches, f"'{command}' not found for '{library}'"
    for version in matches:
        assert (
            version in minimum_os
        ), f"incorrect '{command}' '{version}', expected '{minimum_os}'"


def lipo(debug, target_os, binaries=None, packages=None):
    name = os.environ["NAME"]
    lib_name = f"lib{name}.a"
    library_distribution_directory = os.path.normpath(
        rutils.DISTRIBUTION_DIR + f"/darwin"
    )

    path = (
        f"{library_distribution_directory}/{target_os}/debug/"
        if debug
        else f"{library_distribution_directory}/{target_os}/release/"
    )

    archs = GLOBAL_CONFIG[target_os]["archs"]
    create_fat_binary(
        path + f"{lib_name}",
        target_os,
        archs.keys(),
        lib_name,
        debug,
    )
    if binaries is not None:
        for binary in binaries:
            create_fat_binary(
                path + f"{binary}",
                target_os,
                archs.keys(),
                binary,
                debug,
            )
    if packages is not None:
        for package in packages:
            create_fat_binary(
                path + f"{package}",
                target_os,
                archs.keys(),
                package,
                debug,
            )
    for arch in archs:
        shutil.rmtree(rutils.get_distribution_path(target_os, arch, "", debug))


def create_fat_binary(output, target_os, architectures, cargo_artifact, debug):
    if not os.path.isdir(os.path.dirname(output)):
        os.makedirs(os.path.dirname(output))

    command = ["lipo", "-create"]
    for architecture in architectures:
        command.append(
            rutils.get_distribution_path(target_os, architecture, cargo_artifact, debug)
        )

    command.extend(["-output", output])

    rutils.run_command(command)
