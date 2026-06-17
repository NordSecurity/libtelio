from tests.utils.bindings import DnsRedirect, TpLiteStatsOptions
from typing import List, TYPE_CHECKING

if TYPE_CHECKING:
    from tests.libtelio_client.client import Client


class ClientTpLite:
    def __init__(self, client: "Client") -> None:
        self._client = client

    async def enable_stats_collection(self, config: TpLiteStatsOptions) -> None:
        await self._client.get_proxy().enable_tp_lite_stats_collection(config)

    async def disable_stats_collection(self) -> None:
        await self._client.get_proxy().disable_tp_lite_stats_collection()

    async def get_stats(self):
        return await self._client.get_proxy().get_tp_lite_stats()

    async def set_domain_whitelist(
        self, domains: List[str], redirects: List[DnsRedirect]
    ) -> None:
        await self._client.get_proxy().set_tp_lite_domain_whitelist(domains, redirects)
