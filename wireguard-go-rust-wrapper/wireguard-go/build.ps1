$ErrorActionPreference = "Stop"

# WORKAROUND: CGO has no support for MSVC yet, despite various feature merge requests over time.
# Specifically, Go will try to invoke ar.exe instead of MSVC lib.exe, even if $AR was manually set.
# So we relied at first on TDM-GCC. But when compiling with TDM-GCC, the resulting library
# cannot be linked with the Rust output, since Rust uses MSVC and its libraries.
#
# So let CLang from Visual Studio 2019 and ar.exe from TDM-GCC be our knights in shining armor.
$OLD_CC=$env:CC;
$env:CC="clang.exe";

# WORKAROUND: Rust on Windows will look for LIBs without "lib" prefix, so we're naming ours "wireguard-go.lib"
& go build -ldflags=-w -v -buildmode c-archive -o "$env:OUT_DIR\wireguard-go.lib" wireguard-go

# Restore old $CC EnvVar
$env:CC=$OLD_CC;
