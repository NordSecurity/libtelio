# Building nordvpnlite for OpenWrt locally

## Prerequisites

- **Docker** — all build steps run inside containers, no toolchain installation needed.
  Install from [docs.docker.com/get-docker](https://docs.docker.com/get-docker/).

All commands must be run from the **repository root** (`libtelio/`).

---

## 1. Set build variables

Three variables drive all commands below:

- `ARCH` — the CPU architecture to build for
- `OPENWRT_TARGET` — the OpenWrt SDK target (determines which SDK image is used)
- `OPENWRT_RELEASE` — the OpenWrt release version

Supported `ARCH` values: `x86_64`, `aarch64`, `mipsel`, `mips`, `armv7hf`

`OPENWRT_TARGET` can be any target available in the [OpenWrt SDK image list](https://hub.docker.com/r/openwrt/sdk/tags).
The target determines the CPU variant — make sure it matches your `ARCH`.
Examples used in CI:

| `ARCH`    | `OPENWRT_TARGET`    | CPU variant         |
|-----------|---------------------|---------------------|
| `x86_64`  | `x86_64`            | x86-64              |
| `aarch64` | `mediatek-filogic`  | aarch64 cortex-a53  |
| `aarch64` | `bcm27xx-bcm2711`   | aarch64 cortex-a72  |
| `aarch64` | `bcm27xx-bcm2712`   | aarch64 cortex-a76  |
| `mipsel`  | `ramips-mt7621`     | mipsel 24kc         |
| `mips`    | `ath79-nand`        | mips 24kc           |
| `armv7hf` | `mvebu-cortexa9`    | arm cortex-a9 vfpv3 |

Supported releases: `24.10.4`, `25.12.0`

```sh
ARCH=aarch64
OPENWRT_TARGET=mediatek-filogic
OPENWRT_RELEASE=24.10.4
```

---

## 2. Build the nordvpnlite binary

If `3rd-party/rust_build_utils/` is empty, initialize the submodule first:

```sh
git submodule update --init 3rd-party/rust_build_utils
```

Build the builder image:

```sh
docker build \
  -f 3rd-party/rust_build_utils/builders/build-openwrt-rust/Dockerfile \
  -t build-openwrt-rust \
  3rd-party/rust_build_utils
```

Build the binary:

```sh
docker run --rm \
  -v "$(pwd)":/src \
  -w /src \
  build-openwrt-rust \
  python3 ci/build_libtelio.py build openwrt "$ARCH"
```

Output: `dist/openwrt/release/$ARCH/nordvpnlite`

> A `target/` directory will be created in the repo root — this is Cargo's build cache

---

## 3. Package into .ipk / .apk

Create the output directory and make it writable — the SDK container runs as a non-root user:

```sh
mkdir -p "dist/openwrt/release/${OPENWRT_TARGET}/${OPENWRT_RELEASE}"
chmod -R 0777 "dist/openwrt/release/${OPENWRT_TARGET}"
```

Run the packager:

```sh
docker run --rm \
  -v "$(pwd)":/src \
  "openwrt/sdk:${OPENWRT_TARGET}-${OPENWRT_RELEASE}" \
  bash /src/3rd-party/rust_build_utils/builders/package-openwrt/package.sh \
    /src/clis/nordvpnlite/openwrt/feed \
    src-link \
    "/src/dist/openwrt/release/${ARCH}/nordvpnlite" \
    nordvpnlite \
    "/src/dist/openwrt/release/${OPENWRT_TARGET}/${OPENWRT_RELEASE}"
```

> **Note:** The first run takes 20–40 minutes. The SDK builds all kernel modules for the
> target as part of dependency resolution — this is normal OpenWrt SDK behaviour.

Output: `dist/openwrt/release/$OPENWRT_TARGET/$OPENWRT_RELEASE/nordvpnlite_*.ipk` (OpenWrt 24.10)
or `.apk` (OpenWrt 25.12).
