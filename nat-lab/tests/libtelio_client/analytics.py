from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from tests.libtelio_client.client import Client


class ClientAnalytics:
    """Analytics collection triggers for a `Client`.

    Holds a back-reference to its `Client` and delegates to the libtelio proxy.
    Accessed as `client.analytics`.
    """

    def __init__(self, client: "Client") -> None:
        self._client = client

    async def trigger_event_collection(self) -> None:
        await self._client.get_proxy().trigger_analytics_event()

    async def trigger_qos_collection(self) -> None:
        await self._client.get_proxy().trigger_qos_collection()
