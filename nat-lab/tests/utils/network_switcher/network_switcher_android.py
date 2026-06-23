from .network_switcher import NetworkSwitcher
from tests.utils.connection import Connection


# Android has a single bridged interface and no secondary network, so switching
# is a no-op. Exists so create_network_switcher doesn't assert on VM_ANDROID_1;
# real switching is gated on libtelio running on Android (LLT-4141).
class NetworkSwitcherAndroid(NetworkSwitcher):
    def __init__(self, connection: Connection) -> None:
        self._connection = connection

    async def switch_to_primary_network(self) -> None:
        pass

    async def switch_to_secondary_network(self) -> None:
        pass
