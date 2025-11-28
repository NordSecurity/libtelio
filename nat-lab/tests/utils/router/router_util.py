from .linux_router import LinuxRouter
from .mac_router import MacRouter
from .router import IPStack, Router
from .windows_router import WindowsRouter
from tests.utils.connection import TargetOS, Connection


def new_router(connection: Connection, ip_stack: IPStack) -> Router:
    if connection.target_os == TargetOS.Linux:
        return LinuxRouter(connection, ip_stack)
    if connection.target_os == TargetOS.Windows:
        return WindowsRouter(connection, ip_stack)
    if connection.target_os == TargetOS.Mac:
        return MacRouter(connection, ip_stack)
    assert False, f"target_os '{connection.target_os}' not supported"
