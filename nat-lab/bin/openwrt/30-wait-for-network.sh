#!/bin/sh
set -ex
ubus wait_for network.interface.wan
