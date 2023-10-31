SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
$($SCRIPT_DIR/env.py)
unset SCRIPT_DIR
