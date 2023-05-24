#!/usr/bin/env bash
set -euxo pipefail

SCRIPT_DIR="${SCRIPT_DIR:-$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )}"
BASE_DIR=$(cd "${SCRIPT_DIR}/../.." >/dev/null 2>&1 && pwd )

#using this to set up the kernel module for fullcone nat https://github.com/quintus-lab/NanoPi-R4S-OpenWRT/wiki/1.-Build-FULLCONENAT-for-Linux
sudo apt-get install linux-headers-$(uname -r) build-essential autoconf libtool bison flex libnftnl-dev libmnl-dev -y

#Checking if CONNTRACK_EVENTS are enabled which is needed for this kernel module
if [[ $(cat /boot/config-$(uname -r) | grep CONFIG_NF_CONNTRACK_EVENTS) != "CONFIG_NF_CONNTRACK_EVENTS=y" ]] ; then
    echo "The FULLCONENAT kernel module only works with kernels with CONFIG_NF_CONNTRACK_EVENTS enabled, please enable them on your kernel if you wish to use this module"
    exit 1
fi

pushd "$SCRIPT_DIR/3rd-party/netfilter-full-cone-nat/"
make

sudo modprobe nf_nat
sudo insmod xt_FULLCONENAT.ko
lsmod | grep xt_FULLCONENAT

popd