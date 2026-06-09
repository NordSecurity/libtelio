from tests.utils.bindings import TpLiteStatsOptions
from typing import List, TYPE_CHECKING

if TYPE_CHECKING:
    from tests.libtelio_client.client import Client


class ClientTpLite:
    """Throughput-lite stats collection for a `Client`.

    Holds a back-reference to its `Client` and delegates to the libtelio proxy.
    Accessed as `client.tp_lite`.
    """

    def __init__(self, client: "Client") -> None:
        self._client = client

    async def enable_tp_lite_stats_collection(self, config: TpLiteStatsOptions) -> None:
        await self._client.get_proxy().enable_tp_lite_stats_collection(config)

    async def disable_tp_lite_stats_collection(self) -> None:
        await self._client.get_proxy().disable_tp_lite_stats_collection()

    async def get_tp_lite_stats(self):
        return await self._client.get_proxy().get_tp_lite_stats()

    async def set_tp_lite_whitelisted_domains(self, domains: List[str]) -> None:
        await self._client.get_proxy().set_tp_lite_whitelisted_domains(domains)
