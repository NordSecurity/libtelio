#!/usr/bin/env fish

set --local SCRIPT_DIR (status dirname)
$SCRIPT_DIR/env.py | sed 's/^export /set --global --export /; s/=/ /' | source
