#!/bin/sh
set -eu

CONF=/etc/config/qpkg.conf
QPKG_NAME="NordSecurityMeshnet"

QPKG_ROOT=`/sbin/getcfg $QPKG_NAME Install_Path -f ${CONF}`
export QNAP_QPKG=$QPKG_NAME

TELIOD_CFG_FILE=${QPKG_ROOT}/teliod.cfg
TELIOD_LOG_FILE="/var/log/teliod.log"

# Change the config file permissions. It contains the auth token so we should prohibit it being read by other users
chmod 0660 $TELIOD_CFG_FILE

system_log() {
    local log_level
    case "$1" in
        "INFO") log_level=0 ;;
        "WARN") log_level=1 ;;
        "ERROR") log_level=2 ;;
        *) log_level=0 ;;
    esac
    /sbin/log_tool -u "NordSecurity" -t "$log_level" -a "$2"
}

get_ipc_socket_path() {
    if [ -d "/run" ]; then
        echo "/run/teliod.sock"
    elif [ -d "/var/run" ]; then
        echo "/var/run/teliod.sock"
    else
        system_log ERROR "Neither /run/ nor /var/run/ exists"
        exit 1
    fi
}

case "$1" in
  start)
    ENABLED=$(/sbin/getcfg $QPKG_NAME Enable -u -d FALSE -f $CONF)
    if [ "$ENABLED" != "TRUE" ]; then
        system_log INFO "Package application is disabled."
        exit 1
    fi

    ln -fs ${QPKG_ROOT}/teliod.cgi /home/httpd/cgi-bin/qpkg/teliod.cgi

    SOCKET_PATH=$(get_ipc_socket_path)
    if [ -e "$SOCKET_PATH" ]; then
        system_log INFO "Package application is already running."
        exit 0
    fi

    ${QPKG_ROOT}/teliod start --no-detach $TELIOD_CFG_FILE > $TELIOD_LOG_FILE 2>&1 &
    system_log INFO "Teliod daemon started."
    ;;

  stop)
    SOCKET_PATH=$(get_ipc_socket_path)

    ${QPKG_ROOT}/teliod quit-daemon || true
    sleep 2

    if [ -e "$SOCKET_PATH" ]; then
        system_log WARN "Application socket still exist, forcing shutdown..."
        killall -9 teliod || true
        rm -f "$SOCKET_PATH"
    fi
    system_log INFO "Teliod daemon stopped."
    ;;

  restart)
    $0 stop
    $0 start
    ;;
  remove)
    ;;

  *)
    echo "Usage: $0 {start|stop|restart|remove}"
    exit 1
esac

exit 0
