#!/usr/bin/env bash
which sudo &> /dev/null && sudo $@ || $@
