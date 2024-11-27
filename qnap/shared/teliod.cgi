#!/bin/bash

echo "Content-Type: application/json"
echo ""

# Varibles set by the HTTP web server
#
# $REQUEST_METHOD
# $QUERY_STRING
# $CONTENT_LENGTH

POST_DATA=""

if [[ "$REQUEST_METHOD" == "POST" || "$REQUEST_METHOD" == "PATCH" ]]; then
    read -n $CONTENT_LENGTH POST_DATA
fi

QPKG_DIR="/share/CACHEDEV1_DATA/.qpkg/NordSecurityMeshnet"
APP_TMP_DIR="/tmp/nordsecuritymeshnet"
APP_CMD="$QPKG_DIR/teliod"
CONFIG_FILE="$QPKG_DIR/teliod.cfg"
LOG_FILE="$APP_TMP_DIR/teliod.log"
PID_FILE="$APP_TMP_DIR/teliod.pid"

is_application_running() {
    if [ -f ${PID_FILE} ]; then
        PID=$(cat ${PID_FILE})
        if [ -d /proc/${PID}/ ]; then
            # application is running
            return 0
        fi
    fi
    # application is NOT running
    return 1
}

send_response() {
    local code=$1
    local message=$2
    echo "{\"code\": $code, \"message\": \"$message\"}"
    exit $code
}

start_daemon() {
    if is_application_running; then
        send_response 400 "Application is already running."
    fi
    $APP_CMD daemon $CONFIG_FILE > $LOG_FILE 2>&1 &
    if [[ $? -eq 0 ]]; then
        echo $! > ${PID_FILE}
        send_response 200 "Application started successfully."
    else
        echo $! > ${PID_FILE}
        send_response 500 "Failed to start the application."
    fi
}

stop_daemon() {
    if [ -f ${PID_FILE} ]; then
        PID=$(cat ${PID_FILE})
        kill ${PID} || true
        rm -f ${PID_FILE}
        send_response 200 "Application stopped successfully."
    else
        send_response 400 "Application PID not found."
    fi
}

update_config() {
    NEW_CONFIG=$(echo "$POST_DATA" | jq -r '.config')
    if [[ -z "$NEW_CONFIG" ]]; then
        send_response 400 "No configuration provided."
    fi
    echo "$NEW_CONFIG" > $CONFIG_FILE
    if [[ $? -eq 0 ]]; then
        send_response 200 "Configuration updated successfully."
    else
        send_response 500 "Failed to update configuration."
    fi
}

get_status() {
    if is_application_running; then
        STATUS=$($APP_CMD get-status)
        echo "{\"code\": 200, \"status-report\": $STATUS}"
        exit 0
    else
        send_response 400 "Application is not running."
    fi
}

get_logs() {
    if [[ -f $LOG_FILE ]]; then
        LOGS=$(tail -n 100 $LOG_FILE | jq -R -s '.')
        echo "{\"code\": 200, \"logs\": $LOGS}"
        exit 0
    else
        send_response 404 "Log file not found."
    fi
}

case "$REQUEST_METHOD" in
    POST)
        if [[ "$QUERY_STRING" == "action=start" ]]; then
            start_daemon
        elif [[ "$QUERY_STRING" == "action=stop" ]]; then
            stop_daemon
        else
            send_response 400 "Invalid action for POST."
        fi
        ;;
    PATCH)
        if [[ "$QUERY_STRING" == "action=update-config" ]]; then
            update_config
        else
            send_response 400 "Invalid action for PATCH."
        fi
        ;;
    GET)
        if [[ "$QUERY_STRING" == "action=get-status" ]]; then
            get_status
        elif [[ "$QUERY_STRING" == "action=get-logs" ]]; then
            get_logs
        else
            send_response 400 "Invalid action for GET."
        fi
        ;;
    *)
        send_response 405 "Method not allowed."
        ;;
esac