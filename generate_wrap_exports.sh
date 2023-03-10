#!/usr/bin/env bash

# This script generates a list of bindings functions to be exported when libtelio is built as a dynamic library.
#
# During the build process, the Rust toolchain provides a .DEF file with functions to be exported from
# the dynamic library. This .DEF file will always override any export declarations such as __declspec(dllexport).
# Since Cargo does not know that our FFI functions need be exported, it will omit them from the .DEF file.
# Thus, the dynlib/dll won't expose our bindings.
#
# We can fix this by manually generating a list of exports marked with SWIGEXPORT and pass them as linker options.
# However, MSVC link.exe and GNU LD are incompatible here: MSVC requires an /export: linker switch for each function,
# but GNU LD requires a structured list in a file. We will generate both here.

BINDINGS=$1
LIST_OF_FUNCTIONS=$(cat $BINDINGS.c | egrep '^SWIGEXPORT' | egrep -o '[a-zA-Z0-9_]+\(' | sed 's/(//')


# Generate plain string list for MSVC. Omit, if no functions are exported.
EXPORTS_LIST_MSVC=$BINDINGS.msvc_exports.lst
rm -f $EXPORTS_LIST_MSVC
if [[ ${LIST_OF_FUNCTIONS[@]:+${LIST_OF_FUNCTIONS[@]}} ]]; then
    touch $EXPORTS_LIST_MSVC
    for FUNC in $LIST_OF_FUNCTIONS; do
        echo $FUNC >> $EXPORTS_LIST_MSVC
    done
fi


# Generate structured list for GNU LD. Omit, if no functions are exported - GNU LD cannot parse empty lists!
EXPORTS_LIST_GNULD=$BINDINGS.gnuld_exports.lst
rm -f $EXPORTS_LIST_GNULD
if [[ ${LIST_OF_FUNCTIONS[@]:+${LIST_OF_FUNCTIONS[@]}} ]]; then
    touch $EXPORTS_LIST_GNULD
    echo "{" >> $EXPORTS_LIST_GNULD
    for FUNC in $LIST_OF_FUNCTIONS; do
        echo "    $FUNC;" >> $EXPORTS_LIST_GNULD
    done
    echo "};" >> $EXPORTS_LIST_GNULD
fi
