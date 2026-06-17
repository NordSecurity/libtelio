import asyncio
from tests.log_collector import get_log_without_flush
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from tests.libtelio_client.client import Client


class ClientLog:
    def __init__(self, client: "Client") -> None:
        self._client = client

    def get_stdout(self) -> str:
        return self._client.get_process().get_stdout()

    def get_stderr(self) -> str:
        return self._client.get_process().get_stderr()

    def wait_for_output(self, what: str) -> asyncio.Event:
        event = asyncio.Event()
        self._client.get_runtime().get_output_notifier().notify_output(what, event)
        return event

    async def wait_for(
        self,
        what: str,
        case_insensitive: bool = True,
        count=1,
        not_greater=False,
        incremental=False,
    ) -> None:
        if case_insensitive:
            what = what.lower()

        target_count = count
        if incremental:
            # Get initial log content to establish baseline
            initial_logs = await self.get()
            if case_insensitive:
                initial_logs = initial_logs.lower()

            target_count = initial_logs.count(what) + count

        while True:
            logs = await self.get()
            if case_insensitive:
                logs = logs.lower()
            if not_greater:
                assert (
                    not logs.count(what) > target_count
                ), f'"{what}" appeared {logs.count(what)} times, more than the expected {target_count}.'
            if logs.count(what) >= target_count:
                break
            await asyncio.sleep(1)

    async def get(self) -> str:
        await self.flush()
        return await get_log_without_flush(self._client.get_connection())

    async def flush(self) -> None:
        await self._client.get_proxy().flush_logs()
