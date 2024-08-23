SCRIPT_DIR="$(dirname "$(realpath "$0")")"
$($SCRIPT_DIR/env.py)
unset SCRIPT_DIR
