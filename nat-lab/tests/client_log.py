import asyncio
from tests.log_collector import get_log_without_flush
from tests.utils.connection import TargetOS
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from tests.telio import Client


class ClientLog:
    """Realtime log and process-output access for a running `Client`.

    Holds a back-reference to its `Client` and reads the connection / proxy /
    runtime / process lazily through the client's getters, so it keeps working
    even though those only come into existence once `Client.run()` has started.
    """

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

    async def wait_for_log(
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
            initial_logs = await self.get_log()
            if case_insensitive:
                initial_logs = initial_logs.lower()

            target_count = initial_logs.count(what) + count

        while True:
            logs = await self.get_log()
            if case_insensitive:
                logs = logs.lower()
            if not_greater:
                assert (
                    not logs.count(what) > target_count
                ), f'"{what}" appeared {logs.count(what)} times, more than the expected {target_count}.'
            if logs.count(what) >= target_count:
                break
            await asyncio.sleep(1)

    async def get_log(self) -> str:
        await self.flush_logs()
        return await get_log_without_flush(self._client.get_connection())

    async def clear_system_log(self) -> None:
        """
        Clear the system log on the target machine
        Windows only for now
        """
        connection = self._client.get_connection()
        if connection.target_os == TargetOS.Windows:
            for log_name in ["Application", "System"]:
                await connection.create_process(
                    [
                        "powershell",
                        "-Command",
                        f"Clear-EventLog -LogName {log_name}",
                    ],
                    quiet=True,
                ).execute()

    async def flush_logs(self) -> None:
        await self._client.get_proxy().flush_logs()
