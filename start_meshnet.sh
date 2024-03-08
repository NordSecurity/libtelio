#!/usr/bin/env bash
./target/debug/dtcli login token $NORD_TOKEN
./target/debug/dtcli mesh on nlx1 | grep "{\"identifier.*" | jq '.'