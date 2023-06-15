import re
import asyncio
from typing import Coroutine, Optional, List, Dict
from dataclasses import dataclass
from utils.asyncio_util import run_async, cancel_future
from utils.connection import Connection
from utils.process import Process


@dataclass
class FiveTuple:
    protocol: Optional[str] = None
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    src_port: Optional[int] = None
    dst_port: Optional[int] = None

    def partial_eq(self, comparison: "FiveTuple") -> bool:
        return (
            (self.protocol is None or self.protocol == comparison.protocol)
            and (self.src_ip is None or self.src_ip == comparison.src_ip)
            and (self.dst_ip is None or self.dst_ip == comparison.dst_ip)
            and (self.src_port is None or self.src_port == comparison.src_port)
            and (self.dst_port is None or self.dst_port == comparison.dst_port)
        )


@dataclass
class ConnectionLimits:
    min: Optional[int] = None
    max: Optional[int] = None


@dataclass
class ConnectionTrackerConfig:
    key: str
    limits: ConnectionLimits
    target: FiveTuple


def parse_input(input_string) -> FiveTuple:
    five_tuple = FiveTuple()

    match = re.search(r"proto=(\w+)", input_string)
    if match:
        five_tuple.protocol = match.group(1)

    match = re.search(r"src=([^\s]+)", input_string)
    if match:
        five_tuple.src_ip = match.group(1)

    match = re.search(r"dst=([^\s]+)", input_string)
    if match:
        five_tuple.dst_ip = match.group(1)

    match = re.search(r"sport=(\d+)", input_string)
    if match:
        five_tuple.src_port = int(match.group(1))

    match = re.search(r"dport=(\d+)", input_string)
    if match:
        five_tuple.dst_port = int(match.group(1))

    return five_tuple


class ConnectionTracker:
    def __init__(
        self,
        connection: Connection,
        config: Optional[List[ConnectionTrackerConfig]] = None,
    ):
        self._process: Process = connection.create_process(
            ["conntrack", "-E", "-e", "NEW"]
        )
        self._connection: Connection = connection
        self._stop: Optional[Coroutine] = None
        self._config: Optional[List[ConnectionTrackerConfig]] = config
        self._events: List[FiveTuple] = []
        self._events_wait_list: Dict[str, List[asyncio.Event]] = {}

    def execute(self) -> "ConnectionTracker":
        if not self._config:
            return self

        async def _on_stdout(stdout: str) -> None:
            for line in stdout.splitlines():
                connection = parse_input(line)
                if not self._config or connection is FiveTuple():
                    continue
                self._events.append(connection)

                for cfg in self._config:
                    if cfg.target.partial_eq(connection):
                        events = self._events_wait_list.pop(cfg.key, None)
                        if events:
                            for event in events:
                                event.set()

        command_coroutine = run_async(self._process.execute(stdout_callback=_on_stdout))

        async def stop() -> None:
            if not self._config:
                return

            await cancel_future(command_coroutine)
            await self._connection.create_process(["killall", "conntrack"]).execute()

        self._stop = stop()

        return self

    def get_out_of_limits(self) -> Optional[Dict[str, int]]:
        if not self._config:
            return None

        out_of_limit_connections: Dict[str, int] = {}

        for cfg in self._config:
            count = len(
                [event for event in self._events if cfg.target.partial_eq(event)]
            )
            if cfg.limits.max is not None:
                if count > cfg.limits.max:
                    out_of_limit_connections[cfg.key] = count
                    continue
            if cfg.limits.min is not None:
                if count < cfg.limits.min:
                    out_of_limit_connections[cfg.key] = count
                    continue

        return out_of_limit_connections if bool(out_of_limit_connections) else None

    async def wait_for_event(self, key: str) -> None:
        if not self._config:
            return

        cfg = next((cfg for cfg in self._config if cfg.key == key), None)
        if cfg is None:
            raise Exception(f"Key: {key} not found in connection tracker config")

        count = len([event for event in self._events if cfg.target.partial_eq(event)])
        if count:
            return

        while True:
            event = asyncio.Event()
            if key not in self._events_wait_list:
                self._events_wait_list[key] = [event]
            else:
                self._events_wait_list[key].append(event)
            await event.wait()

    async def stop(self) -> None:
        if self._stop:
            await self._stop

    async def __aenter__(self) -> "ConnectionTracker":
        return self.execute()

    async def __aexit__(self, exc_type, exc, tb):
        await self.stop()
