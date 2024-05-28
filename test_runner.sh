#!/usr/bin/env bash

if command -v sudo &> /dev/null; then
    sudo -E $@
else
    $@
fi
