# Debug Symbols and Build IDs

Release builds of libtelio ship stripped libraries. Their debug info is published in a separate
file next to each library. A library and its debug file carry the same ID. The ID tells you which
debug file belongs to which library, and the debug file turns an address from a crash or a
backtrace into a function name and a source line.

Release builds check this automatically: `ci/build_libtelio.py` runs the checks from
`ci/debug_ids.py` after every release build. On Linux, Android, macOS, iOS and tvOS the build fails
if an ID is missing, the IDs don't match, or the debug file has no debug info.

On Windows the check is weaker, because MSVC has no command line tool that reads the GUID and age
from a PDB. The build fails only if the DLL has no CodeView record, the record names a different
PDB file, or the PDB is missing or empty. A stale or broken `telio.pdb` passes this check. The
check runs only for MSVC builds.

The commands below check the same things by hand. On Windows they also compare the GUID and age.

## Where the addresses come from

When libtelio panics, it logs a backtrace at ERROR level, one line per function:

```text
backtrace:   7 libtelio.so 6e432711b2782a8c5e9f0190da1c6912a564a63e 0x5786dd uniffi_telio_fn_method_telio_set_meshnet
```

The columns are the library, its ID, the address relative to the start of the library and the
function name. Errors returned over FFI carry the same data: `TelioError.backtrace().functions()`
gives the library, ID, address and name of each function. Release libraries only contain their
exported functions, so the name is often wrong. Use the ID to pick the debug file and pass the
address to the commands below. Most addresses point at the instruction after a call. Subtract 1
from them to get the line of the call itself, for example `0x5786dd` becomes `0x5786dc`.

## Resolving addresses with a script

`ci/symbolize.py` does the manual steps below in one go. It checks that the debug file belongs to
the library, then prints the function, file and line of each address. Inlined functions are
printed innermost first:

```bash
ci/symbolize.py --return-address libtelio.so libtelio.so.debug 0x5786dd
```

```text
libtelio.so and libtelio.so.debug have ID 6e432711b2782a8c5e9f0190da1c6912a564a63e
0x5786dd
  <telio_core::device::Device>::set_config at .../crates/telio-core/src/device.rs:766:29
```

The ID is printed in the same format as the ID column of libtelio's backtraces, so the two can be
compared directly. It works the same way for `libtelio.dylib` with `libtelio.dylib.dSYM` (the dSYM
of one architecture) and for `telio.dll` with `telio.pdb`. On Windows it adds the image base
itself, and the PDB must be next to the DLL. Pass `--return-address` for addresses from a
backtrace, so it looks up the call (the address minus 1). `--json` prints the result as JSON. It
needs `llvm-symbolizer`, `llvm-readelf`, `llvm-dwarfdump`, `llvm-readobj` and `llvm-pdbutil` from
LLVM 14 or newer, on `PATH` or in the directory passed with `--llvm-bin`.

## Where the files are

| Platform | Library | Debug file | ID |
|---|---|---|---|
| Linux | `dist/linux/release/<arch>/libtelio.so` | `libtelio.so.debug` | GNU build ID |
| Android | `dist/android/release/<abi>/libtelio.so` | `libtelio.so.debug` | GNU build ID |
| macOS, iOS, tvOS | `dist/darwin/<os>/release/<arch>/libtelio.dylib` | `libtelio.dylib.dSYM` | Mach-O UUID |
| Windows | `dist/windows/release/<arch>/telio.dll` | `telio.pdb` | PDB GUID and age |

In the release `darwin.zip`, the libraries of each OS are merged into one file
(`dist/darwin/<os>/release/libtelio.dylib`) and the dSYM of each architecture is in
`libtelio.dylib.dSYM/<arch>/`. Point the tools at
`libtelio.dylib.dSYM/<arch>/Contents/Resources/DWARF/libtelio.dylib` there.

## Linux and Android

1. Read the build ID of the library and of the debug file. Both must print the same value:

   ```bash
   readelf -n libtelio.so | grep 'Build ID'
   readelf -n libtelio.so.debug | grep 'Build ID'
   ```

   ```text
       Build ID: 6e432711b2782a8c5e9f0190da1c6912a564a63e
       Build ID: 6e432711b2782a8c5e9f0190da1c6912a564a63e
   ```

   `llvm-readelf` (also in the Android NDK) takes the same options. On macOS, `file libtelio.so`
   shows the ID as `BuildID[sha1]=6e432711...`.

2. Check that the debug file has debug info. This must print one `PROGBITS` line:

   ```bash
   readelf -S -W libtelio.so.debug | grep ' .debug_info '
   ```

3. Turn an address into a function and a source line. The address is relative to the start of
   the library:

   ```bash
   llvm-symbolizer --obj=libtelio.so.debug 0x5786dc
   ```

   ```text
   <telio_core::device::Device>::set_config
   .../crates/telio-core/src/device.rs:766:29
   ```

   `addr2line -f -i -C -e libtelio.so.debug 0x5786dc` gives the same result, but it has to be
   built for the architecture of the library, for example `aarch64-linux-gnu-addr2line`.

## macOS, iOS and tvOS

1. Read the UUID of the library and of the dSYM. Both must print the same value. Universal
   libraries print one line per architecture:

   ```bash
   dwarfdump --uuid libtelio.dylib
   dwarfdump --uuid libtelio.dylib.dSYM/x86_64/Contents/Resources/DWARF/libtelio.dylib
   dwarfdump --uuid libtelio.dylib.dSYM/aarch64/Contents/Resources/DWARF/libtelio.dylib
   ```

   ```text
   UUID: 4C627B1B-8DF1-32B9-8409-F4A978ADC150 (x86_64) libtelio.dylib
   UUID: E6234D9D-5C4A-3FE4-8A75-9082E125F1E9 (arm64) libtelio.dylib
   UUID: 4C627B1B-8DF1-32B9-8409-F4A978ADC150 (x86_64) libtelio.dylib.dSYM/x86_64/Contents/Resources/DWARF/libtelio.dylib
   UUID: E6234D9D-5C4A-3FE4-8A75-9082E125F1E9 (arm64) libtelio.dylib.dSYM/aarch64/Contents/Resources/DWARF/libtelio.dylib
   ```

2. Check that the dSYM has debug info. This must print a size bigger than zero. A dSYM without
   `__debug_info` can only map addresses to exported functions:

   ```bash
   dwarfdump --show-section-sizes libtelio.dylib.dSYM/aarch64/Contents/Resources/DWARF/libtelio.dylib | grep __debug_info
   ```

   ```text
   __debug_info      23140636 (23.11%)
   ```

3. Turn an address into a function and a source line. `-l 0` is needed because the address is
   relative to the start of the library. `-i` also prints inlined functions:

   ```bash
   atos -o libtelio.dylib.dSYM/aarch64/Contents/Resources/DWARF/libtelio.dylib -arch arm64 -l 0 -i 0x23f0a0
   ```

   ```text
   _RNvMs2_NtCs5FjpyIY3MR0_10telio_core6deviceNtB5_6Device10set_config (in libtelio.dylib) (device.rs:767)
   ```

## Windows

1. Read the GUID and age that the DLL expects from its PDB. Run it in a Developer Command Prompt
   for Visual Studio:

   ```bat
   dumpbin /headers telio.dll | findstr RSDS
   ```

   ```text
   ... Format: RSDS, {B4F9508D-F4F5-4828-96D1-2998FB5D706F}, 1, telio.pdb
   ```

2. Read the GUID and age of the PDB. Visual Studio has no command line tool for this, so use
   `llvm-pdbutil` from LLVM. Both values must match the DLL:

   ```bash
   llvm-pdbutil dump --summary telio.pdb
   ```

   ```text
     Age: 1
     GUID: {B4F9508D-F4F5-4828-96D1-2998FB5D706F}
   ```

3. Turn an address into a function and a source line. Keep `telio.pdb` next to `telio.dll`.
   `llvm-symbolizer` expects a virtual address, so add the image base of the DLL to an address
   that is relative to the start of the DLL:

   ```bash
   llvm-readobj --file-headers telio.dll | grep ImageBase
   llvm-symbolizer --obj=telio.dll 0x180062af0
   ```

   ```text
     ImageBase: 0x180000000
   uniffi_telio_fn_method_telio_set_meshnet
   C:\...\libtelio.uniffi.rs:1448:0
   ```
