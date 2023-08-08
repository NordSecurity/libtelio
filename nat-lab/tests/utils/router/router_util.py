from .linux_router import LinuxRouter
from .mac_router import MacRouter
from .router import Router
from .windows_router import WindowsRouter
from utils.connection import TargetOS, Connection


def new_router(connection: Connection) -> Router:
    if connection.target_os == TargetOS.Linux:
        return LinuxRouter(connection)
    if connection.target_os == TargetOS.Windows:
        return WindowsRouter(connection)
    if connection.target_os == TargetOS.Mac:
        return MacRouter(connection)
    assert False, f"target_os '{connection.target_os}' not supported"
