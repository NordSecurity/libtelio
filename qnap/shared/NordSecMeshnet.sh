#!/bin/sh
CONF=/etc/config/qpkg.conf
QPKG_NAME="NordSecurityMeshnet"


QPKG_ROOT=`/sbin/getcfg $QPKG_NAME Install_Path -f ${CONF}`
APACHE_ROOT=`/sbin/getcfg SHARE_DEF defWeb -d Qweb -f /etc/config/def_share.info`
export QNAP_QPKG=$QPKG_NAME

NORDSECMESHNET_DIR=/tmp/nordsecuritymeshnet/
TELIOD_PID_FILE=${NORDSECMESHNET_DIR}/teliod.pid

case "$1" in
  start)
    ENABLED=$(/sbin/getcfg $QPKG_NAME Enable -u -d FALSE -f $CONF)
    if [ "$ENABLED" != "TRUE" ]; then
        echo "$QPKG_NAME is disabled."
        exit 1
    fi

    ln -s ${QPKG_ROOT}/web /home/Qhttpd/Web/NordSecurityMeshnet
    ln -s ${QPKG_ROOT}/teliod.cgi /home/httpd/cgi-bin/qpkg/teliod.cgi
    mkdir -p -m 0755 $NORDSECMESHNET_DIR

    if [ -e ${TELIOD_PID_FILE} ]; then
        PID=$(cat ${TELIOD_PID_FILE})
        if [ -d /proc/${PID}/ ]; then
          echo "${QPKG_NAME} is already running."
          exit 0
        fi
    fi

    ${QPKG_ROOT}/teliod daemon ${QPKG_ROOT}/teliod.cfg &
    echo $! > ${TELIOD_PID_FILE}
    ;;

  stop)
    if [ -e ${TELIOD_PID_FILE} ]; then
      PID=$(cat ${TELIOD_PID_FILE})
      kill -9 ${PID} || true
      rm -f ${TELIOD_PID_FILE}
    fi
    rm -f /run/teliod.sock
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
