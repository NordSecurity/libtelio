#!/bin/sh
set -e

opkg --version
uname -a

touch /ready

exec sleep infinity
