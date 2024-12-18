#!/bin/sh
set -eu

CONF=/etc/config/qpkg.conf
QPKG_NAME="NordSecurityMeshnet"
QPKG_ROOT=`/sbin/getcfg $QPKG_NAME Install_Path -f ${CONF}`

exec "${QPKG_ROOT}/teliod" cgi
