from utils.connection import Connection
from utils.connection_util import get_libtelio_binary_path
from utils.process import Process


class InterDerpClient:
    _process: Process

    def __init__(
        self, connection: Connection, server_1: str, server_2: str, sk1: str, sk2: str
    ) -> None:
        self._stop = None
        self._process = connection.create_process([
            get_libtelio_binary_path("interderpcli", connection),
            "-v",
            "--derp-1",
            server_1,
            "--derp-2",
            server_2,
            "--secret-key-1",
            sk1,
            "--secret-key-2",
            sk2,
        ])

    async def execute(self) -> None:
        await self._process.execute()
