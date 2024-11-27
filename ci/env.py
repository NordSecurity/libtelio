#!/usr/bin/env python3

import os

LIBTELIO_ENV_MOOSE_RELEASE_TAG = "v14.2.0-libtelioApp"
LIBTELIO_ENV_NAT_LAB_DEPS_TAG = "v0.0.30"
LIBTELIO_ENV_ANDROID_BUILDER_TAG = "v0.0.3"
LIBTELIO_ENV_LINUX_BUILDER_TAG = "v0.0.7"
LIBTELIO_ENV_WINDOWS_BUILDER_TAG = "v0.0.3"
LIBTELIO_ENV_UNIFFI_GENERATORS_TAG = "v0.25.0-8"


def set_sh():
    print(f"export LIBTELIO_ENV_MOOSE_RELEASE_TAG={LIBTELIO_ENV_MOOSE_RELEASE_TAG}")
    print(f"export LIBTELIO_ENV_NAT_LAB_DEPS_TAG={LIBTELIO_ENV_NAT_LAB_DEPS_TAG}")
    print(f"export LIBTELIO_ENV_ANDROID_BUILDER_TAG={LIBTELIO_ENV_ANDROID_BUILDER_TAG}")
    print(f"export LIBTELIO_ENV_LINUX_BUILDER_TAG={LIBTELIO_ENV_LINUX_BUILDER_TAG}")
    print(f"export LIBTELIO_ENV_WINDOWS_BUILDER_TAG={LIBTELIO_ENV_WINDOWS_BUILDER_TAG}")


def set_ps1():
    print(f'$env:LIBTELIO_ENV_MOOSE_RELEASE_TAG="{LIBTELIO_ENV_MOOSE_RELEASE_TAG}"')
    print(f'$env:LIBTELIO_ENV_NAT_LAB_DEPS_TAG="{LIBTELIO_ENV_NAT_LAB_DEPS_TAG}"')
    print(f'$env:LIBTELIO_ENV_ANDROID_BUILDER_TAG="{LIBTELIO_ENV_ANDROID_BUILDER_TAG}"')
    print(f'$env:LIBTELIO_ENV_LINUX_BUILDER_TAG="{LIBTELIO_ENV_LINUX_BUILDER_TAG}"')
    print(f'$env:LIBTELIO_ENV_WINDOWS_BUILDER_TAG="{LIBTELIO_ENV_WINDOWS_BUILDER_TAG}"')


if __name__ == "__main__":
    if os.name == "nt":
        set_ps1()
    else:
        set_sh()
