import asyncio
import platform
import re
from contextlib import asynccontextmanager
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import Optional, List, Dict, AsyncIterator
from utils.connection import Connection
from utils.ping import Ping
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

    def get_key(self) -> str:
        return self.key


def parse_input(input_string) -> FiveTuple:
    five_tuple = FiveTuple()

    print(datetime.now(), "Conntracker reported new connection:", input_string)

    match = re.search(r"\[NEW\] (\w+)", input_string)
    if match:
        if match.group(1) == "icmp":
            if "type=0" in input_string or "type=8" in input_string:
                five_tuple.protocol = match.group(1)
        elif match.group(1) == "icmpv6":
            if "type=128" in input_string or "type=129" in input_string:
                five_tuple.protocol = match.group(1)
        else:
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


class SynchronizeState(Enum):
    NOT_SYNCED = 0
    WAITING_TO_SYNC = 1
    RECEIVED_SYNC_PING = 2


class ConnectionTracker:
    def __init__(
        self,
        connection: Connection,
        configuration: Optional[List[ConnectionTrackerConfig]] = None,
    ):
        self._process: Process = connection.create_process(
            ["conntrack", "-E", "-e", "NEW"]
        )
        self._connection: Connection = connection
        self._config: Optional[List[ConnectionTrackerConfig]] = configuration
        self._events: List[FiveTuple] = []
        self._lock: asyncio.Lock = asyncio.Lock()
        self._sync_state: SynchronizeState = SynchronizeState.NOT_SYNCED
        self._sync_event: asyncio.Event = asyncio.Event()
        self._sync_connection: FiveTuple = FiveTuple(
            protocol="icmp", dst_ip="127.0.0.2"
        )

    async def on_stdout(self, stdout: str) -> None:
        if not self._config:
            return

        async with self._lock:
            for line in stdout.splitlines():
                connection = parse_input(line)
                if connection is FiveTuple():
                    continue

                if self._sync_state == SynchronizeState.WAITING_TO_SYNC:
                    if self._sync_connection.partial_eq(connection):
                        self._sync_state = SynchronizeState.RECEIVED_SYNC_PING
                        continue

                matching_configs = [
                    cfg for cfg in self._config if cfg.target.partial_eq(connection)
                ]
                if not matching_configs:
                    continue

                self._events.append(connection)

            # we received the sync ping
            if self._sync_state == SynchronizeState.RECEIVED_SYNC_PING:
                print(datetime.now(), "ConnectionTracker sending _sync_event")
                self._sync_event.set()

    async def execute(self) -> None:
        if platform.system() == "Darwin":
            return None
        if not self._config:
            return

        await self._process.execute(stdout_callback=self.on_stdout)

    async def get_out_of_limits(self) -> Optional[Dict[str, int]]:
        if platform.system() == "Darwin":
            return None
        if not self._config:
            return None

        await self.synchronize()

        out_of_limit_connections: Dict[str, int] = {}

        for cfg in self._config:
            async with self._lock:
                count = len(
                    [event for event in self._events if cfg.target.partial_eq(event)]
                )
            if cfg.limits.max is not None:
                if count > cfg.limits.max:
                    out_of_limit_connections[cfg.key] = count
                    print(
                        datetime.now(),
                        "ConnectionTracker for",
                        cfg.target.src_ip,
                        cfg.key,
                        "is over the limit:",
                        count,
                        ">",
                        cfg.limits.max,
                    )
                    continue
            if cfg.limits.min is not None:
                if count < cfg.limits.min:
                    out_of_limit_connections[cfg.key] = count
                    print(
                        datetime.now(),
                        "ConnectionTracker for",
                        cfg.target.src_ip,
                        cfg.key,
                        "is under the limit:",
                        count,
                        "<",
                        cfg.limits.min,
                    )
                    continue

        return out_of_limit_connections if bool(out_of_limit_connections) else None

    async def synchronize(self):
        if not self._config:
            return None

        async with self._lock:
            self._sync_state = SynchronizeState.WAITING_TO_SYNC
        # wait to synchronize over a known event
        async with Ping(self._connection, "127.0.0.2").run():
            print(datetime.now(), "ConnectionTracker waiting for _sync_event")
            await self._sync_event.wait()
            print(datetime.now(), "ConnectionTracker got _sync_event")
            async with self._lock:
                self._sync_event.clear()
                self._sync_state = SynchronizeState.NOT_SYNCED

    @asynccontextmanager
    async def run(self) -> AsyncIterator["ConnectionTracker"]:
        async with self._process.run(stdout_callback=self.on_stdout):
            await self._process.wait_stdin_ready()
            # initialization is just waiting for first conntrack event
            await asyncio.sleep(0.1)  # take a nap to settle things in
            await self.synchronize()
            yield self
