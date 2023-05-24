#!/usr/bin/env bash

# Prep
echo "deb-src https://deb.debian.org/debian stable main" >> /etc/apt/sources.list
export DEBIAN_FRONTEND=noninteractive
apt-get install -qy devscripts dpkg-dev debhelper
apt-get update

# Make and enter directory
mkdir stun-server
cd stun-server

# Get stun-server source
apt-get source stun-server

# Patch and build package
cd stun-*
patch stun.cxx < ../../timeval-fix.patch
debuild -b -us -uc

# Install package
cd ../
dpkg -i stun-server_*.deb
cd ../

# Remove files
sed -i '/deb-src/d' /etc/apt/sources.list
rm -r stun-server*
rm timeval-fix.patch
