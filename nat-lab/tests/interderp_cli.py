import os
from tests.utils.connection import Connection, TargetOS
from tests.utils.connection_util import get_libtelio_binary_path
from tests.utils.logger import log
from tests.utils.process import Process, ProcessExecError


class InterDerpClient:
    _process: Process
    _connection: Connection

    def __init__(
        self,
        connection: Connection,
        server_1: str,
        server_2: str,
        sk1: str,
        sk2: str,
        instance_id: int,
    ) -> None:
        self._stop = None
        self._instance_id = instance_id
        self._process = connection.create_process(
            [
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
            ],
            quiet=True,
        )
        self._connection = connection

    async def execute(self) -> None:
        async def on_output(output: str) -> None:
            log.info("interderpcli_%s: %s", self._instance_id, output)

        try:
            await self._process.execute(on_output, on_output)
        except ProcessExecError as e:
            log.error("Interderpcli process execution failed: %s", e)
            await self.save_logs()
            raise

    async def get_log(self) -> str:
        process = (
            self._connection.create_process(["type", "interderpcli.log"], quiet=True)
            if self._connection.target_os == TargetOS.Windows
            else self._connection.create_process(
                ["cat", "./interderpcli.log"], quiet=True
            )
        )
        await process.execute()
        return process.get_stdout()

    async def save_logs(self) -> None:
        if os.environ.get("NATLAB_SAVE_LOGS") is None:
            return

        log_dir = "logs"
        os.makedirs(log_dir, exist_ok=True)

        log_content = await self.get_log()

        if self._connection.target_os == TargetOS.Linux:
            process = self._connection.create_process(
                ["cat", "/etc/hostname"], quiet=True
            )
            await process.execute()
            container_id = process.get_stdout().strip()
        else:
            container_id = str(self._connection.target_os.name)

        filename = (
            "preconditions_interderpcli_"
            + container_id
            + "_"
            + str(self._instance_id)
            + ".log"
        )
        if len(filename.encode("utf-8")) > 256:
            filename = f"{filename[:251]}.log"

            i = 0
            while os.path.exists(os.path.join(log_dir, filename)):
                filename = f"{filename[:249]}_{i}.log"
                i += 1

        with open(
            os.path.join(log_dir, filename),
            "w",
            encoding="utf-8",
        ) as f:
            f.write(log_content)
