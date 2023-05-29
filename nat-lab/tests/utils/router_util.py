from utils.connection import TargetOS, Connection
from utils import Router, LinuxRouter, WindowsRouter, MacRouter


def new_router(connection: Connection) -> Router:
    if connection.target_os == TargetOS.Linux:
        return LinuxRouter(connection)
    elif connection.target_os == TargetOS.Windows:
        return WindowsRouter(connection)
    elif connection.target_os == TargetOS.Mac:
        return MacRouter(connection)
    else:
        assert False, f"target_os '{connection.target_os}' not supported"
