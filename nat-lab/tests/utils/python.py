from tests.config import ANDROID_DEVICE_TMP
from tests.utils.connection import Connection, ConnectionTag, TargetOS


def get_python_binary(connection: Connection) -> str:
    """
    Returns the correct python binary name for each platform or the
    full path where needed.
    """
    if connection.tag == ConnectionTag.VM_ANDROID_1:
        # Launcher (pushed by copy_binaries) that re-execs into the Termux python
        # via run-as, since the bionic interpreter + libtelio.so live in Termux's
        # app-private home. See bin/android/natlab-python.
        return f"{ANDROID_DEVICE_TMP}natlab-python"
    if connection.target_os == TargetOS.Windows:
        return "python"
    if connection.target_os == TargetOS.Mac:
        # Using the 'env python3' on macOS fails with:
        # xcode-select: error: no developer tools were found at '/Applications/Xcode.app',
        # and no install could be requested (perhaps no UI is present), please install manually from 'developer.apple.com'.
        #
        # we need to specify the exact path of the custom installed python
        return "/usr/local/bin/python3"
    return "python3"
