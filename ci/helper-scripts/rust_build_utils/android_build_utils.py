import os
import shutil
import rust_build_utils.rust_utils as rutils
from rust_build_utils.rust_utils_config import GLOBAL_CONFIG, NDK_IMAGE_PATH

NDK_VERSION = "r26"
TOOLCHAIN = (
    f"{NDK_IMAGE_PATH}/android-ndk-{NDK_VERSION}/toolchains/llvm/prebuilt/linux-x86_64"
)

NDK_MAP = {
    "x86_64": "x86_64-linux-android",
    "aarch64": "aarch64-linux-android",
    "i686": "i686-linux-android",
    "armv7": "arm-linux-androideabi",
}


def strip_android(config):
    strip_dir = rutils.get_distribution_path(
        config.target_os, config.arch, f"../stripped/", config.debug
    )
    unstrip_dir = rutils.get_distribution_path(
        config.target_os, config.arch, f"../unstripped", config.debug
    )
    if os.path.exists(strip_dir):
        shutil.rmtree(strip_dir)
    os.makedirs(strip_dir)
    if os.path.exists(unstrip_dir):
        shutil.rmtree(unstrip_dir)
    os.makedirs(unstrip_dir)

    arch_dir = rutils.get_distribution_path(
        config.target_os, config.arch, "", config.debug
    )
    renamed_arch = GLOBAL_CONFIG[config.target_os]["archs"][config.arch]["dist"]
    shutil.copytree(
        arch_dir,
        f"{unstrip_dir}/{renamed_arch}",
    )
    shutil.copytree(
        arch_dir,
        f"{strip_dir}/{renamed_arch}",
    )

    shutil.rmtree(arch_dir)
    strip = f"{TOOLCHAIN}/bin/llvm-strip"
    rutils.run_command([strip, f"{strip_dir}/{renamed_arch}/{config.lib_name}"])
