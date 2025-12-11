import asyncio
from tests.helpers import request_json
from tests.utils.connection import Connection
from tests.utils.process import ProcessExecError
from typing import Any
from urllib.parse import quote

FAKEFM_PORT_DEFAULT = 7777

SYSTEMCTL_UNIT_NOT_ACTIVE = 3  # LSB return code: "program is not running"


async def stop_service(conn: Connection, service: str) -> None:

    await conn.create_process(["systemctl", "stop", service]).execute()

    try:
        proc = await conn.create_process(["systemctl", "is-active", service]).execute()
        state = proc.get_stdout().strip()

        if state != "inactive":
            raise RuntimeError(f"Service '{service}' did not stop, state={state}")
    except ProcessExecError as e:
        state = e.stdout.strip()
        if e.returncode == SYSTEMCTL_UNIT_NOT_ACTIVE and state == "inactive":
            return

        raise RuntimeError(
            f"Service '{service}' did not stop, "
            f"state={state or 'unknown'}, returncode={e.returncode}"
        ) from e


async def wait_for_service_active(
    conn: Connection,
    service: str,
    timeout: float = 10.0,
) -> None:
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout
    last_state = "unknown"

    while True:
        try:
            proc = await conn.create_process(
                ["systemctl", "is-active", service]
            ).execute()
            state = proc.get_stdout().strip()
        except ProcessExecError as e:
            state = e.stdout.strip() or "unknown"

        last_state = state

        if state == "active":
            return

        if loop.time() > deadline:
            raise TimeoutError(
                f"Service '{service}' did not become active within "
                f"{timeout:.1f}s (last state={last_state})"
            )

        await asyncio.sleep(1)


async def start_service(
    conn: Connection,
    service: str,
) -> None:
    await conn.create_process(["systemctl", "start", service]).execute()


class FakeFmError(RuntimeError):
    pass


class FakeFmClient:
    def __init__(self, host: str, port: int) -> None:
        self.host = host
        self.port = port
        self.address = f"http://{self.host}:{self.port}"

    @classmethod
    async def create(
        cls,
        host: str,
        port: int = FAKEFM_PORT_DEFAULT,
    ) -> "FakeFmClient":
        inst = cls(host, port)
        await inst._api_call("help")  # Verify that api works
        return inst

    async def _api_call(self, endpoint: str) -> dict[str, Any]:
        url = f"{self.address}/{endpoint}"
        try:
            data = await request_json("GET", url)
        except Exception as exc:
            raise FakeFmError(f"FakeFm API call '{endpoint}' failed: {exc}") from exc

        if not data.get("success"):
            raise FakeFmError(f"FakeFm API call '{endpoint}' failed: {data!r}")

        return data

    async def add_allowed_user(self, username: str, password: str) -> None:
        cmd = f"addAllowedUser?username={quote(username)}&password={password}"
        await self._api_call(cmd)

    async def set_users_limits(self, limit: int) -> None:
        cmd = f"setUsersLimits?limit={limit}"
        await self._api_call(cmd)
