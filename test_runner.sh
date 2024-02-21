#!/usr/bin/env bash

if command -v sudo &> /dev/null; then
    sudo $@
else
    $@
fi
