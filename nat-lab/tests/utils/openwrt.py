import asyncio
import asyncssh
import json
from tests.utils.connection import Connection
from tests.utils.logger import log
from tests.utils.process import ProcessExecError


def _iface_uptime(status: dict) -> float | None:
    """Extract the interface uptime from a netifd status."""
    uptime = status.get("uptime")
    if not isinstance(uptime, (int, float)):
        return None
    return float(uptime)


def _iface_came_up_at(uptime: float | None, now: float) -> float | None:
    """Return the uptime timestamp when the interface last came up, or None."""
    if uptime is None:
        return None
    return now - uptime


def _came_up_after(
    came_up_at: float | None,
    not_before: float | None,
) -> bool:
    """Return True if the interface came up after *not_before*."""
    if not_before is None:
        return True
    if came_up_at is None:
        return False

    return came_up_at > not_before


async def network_interface_status(connection: Connection, iface: str) -> dict:
    """Query netifd for the current status of a network interface."""
    proc = await connection.create_process(
        ["ubus", "call", f"network.interface.{iface}", "status"]
    ).execute()
    return json.loads(proc.get_stdout())


async def router_uptime(connection: Connection) -> float:
    """Read the uptime from ``/proc/uptime`` in seconds."""
    proc = await connection.create_process(["cat", "/proc/uptime"]).execute()
    fields = proc.get_stdout().split()
    if not fields:
        raise ValueError("empty output from /proc/uptime")
    return float(fields[0])


async def wait_for_wan_up(
    connection: Connection,
    iface: str = "wan",
    not_before: float | None = None,
    timeout: float = 60.0,
) -> None:
    """Poll netifd until the WAN interface is up.

    If *not_before* is given (a router uptime timestamp just before a network change),
    the interface must have come up after that moment.

    Raises TimeoutError if the interface is not up within *timeout* seconds.
    """
    last_exc: Exception | None = None

    async def _check_status() -> None:
        nonlocal last_exc
        while True:
            try:
                s = await network_interface_status(connection, iface)
                now = await router_uptime(connection)
            except Exception as exc:  # pylint: disable=broad-exception-caught
                last_exc = exc
                log.debug(
                    "wait_for_wan_up: could not read %s status: %s: %s",
                    iface,
                    type(exc).__name__,
                    exc,
                )
                await asyncio.sleep(1.0)
                continue

            last_exc = None
            iface_uptime = _iface_uptime(s)
            came_up_at = _iface_came_up_at(iface_uptime, now)
            came_up_after = _came_up_after(came_up_at, not_before)

            if s.get("up") and not s.get("pending") and came_up_after:
                log.debug(
                    "wait_for_wan_up: %s is up "
                    "(iface uptime=%ss, came_up_at=%s, not_before=%s)",
                    iface,
                    iface_uptime,
                    came_up_at,
                    not_before,
                )
                return

            log.debug(
                "wait_for_wan_up: %s not ready yet "
                "(up=%s, pending=%s, "
                "iface uptime=%s, came_up_at=%s, not_before=%s)",
                iface,
                s.get("up"),
                s.get("pending"),
                iface_uptime,
                came_up_at,
                not_before,
            )
            await asyncio.sleep(1.0)

    try:
        await asyncio.wait_for(_check_status(), timeout)
    except asyncio.TimeoutError as exc:
        if last_exc is not None:
            raise TimeoutError(
                f"{iface} not up within {timeout}s; last error: {last_exc!r}"
            ) from last_exc
        raise TimeoutError(f"{iface} not up within {timeout}s") from exc


async def wait_until_unreachable_after_reboot(connection: Connection, delay: int = 1):
    """Wait until the existing connection becomes unreachable after rebooting."""
    while True:
        try:
            await connection.create_process(["true"]).execute()
        except (
            asyncssh.misc.ConnectionLost,
            asyncssh.misc.ChannelOpenError,
            asyncssh.misc.DisconnectError,
            OSError,
            asyncio.TimeoutError,
        ):
            log.debug("VM became unreachable — reboot likely in progress.")
            return
        await asyncio.sleep(delay)


async def wait_for_router_dns(
    connection: Connection, host: str, attempts: int = 20, interval: float = 2.0
) -> None:
    """Wait until the OpenWrt router's dnsmasq can resolve `host`.

    After a WAN-down or reboot the router's resolver needs a moment to recover,
    so probe it with a light nslookup before issuing requests that depend on it.
    """
    for attempt in range(1, attempts + 1):
        try:
            await connection.create_process(["nslookup", host], quiet=True).execute()
            return
        except ProcessExecError:
            if attempt == attempts:
                raise
            log.warning(
                "[%s] router cannot resolve %s yet (attempt %d/%d), waiting...",
                connection.tag.name,
                host,
                attempt,
                attempts,
            )
            await asyncio.sleep(interval)


async def daemon_pid(connection: Connection) -> str:
    """PID of the procd-managed daemon, empty string when it is not running."""
    try:
        proc = await connection.create_process(
            ["pgrep", "-f", "nordvpnlite start --no-detach"]
        ).execute()
    except ProcessExecError:
        return ""

    pid = proc.get_stdout().strip()
    assert (
        len(pid.split()) <= 1
    ), f"expected a single daemon process, pgrep returned '{pid}'"
    return pid


async def wait_for_new_daemon_pid(connection: Connection, old_pid: str) -> str:
    """Wait until a new nordvpnlite daemon process replaces old_pid, returning new pid."""
    while True:
        pid = await daemon_pid(connection)
        if pid and pid != old_pid:
            return pid
        await asyncio.sleep(1)


async def is_autostart_enabled(connection: Connection) -> bool:
    try:
        await connection.create_process(
            ["/etc/init.d/nordvpnlite", "enabled"]
        ).execute()
        return True
    except ProcessExecError:
        return False
