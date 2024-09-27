import asyncio
import platform
import re
from collections import defaultdict
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Optional, List, Dict, AsyncIterator
from utils.connection import Connection
from utils.ping import ping
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


class EventType(Enum):
    """Event type reported by conntrack"""

    NEW = "NEW"
    UPDATE = "UPDATE"
    DESTROY = "DESTROY"


class TcpState(Enum):
    """TCP specific state for an event"""

    SYN_SENT = "SYN_SENT"
    SYN_RECV = "SYN_RECV"
    ESTABLISHED = "ESTABLISHED"
    FIN_WAIT = "FIN_WAIT"
    CLOSE_WAIT = "CLOSE_WAIT"
    LAST_ACK = "LAST_ACK"
    TIME_WAIT = "TIME_WAIT"
    CLOSE = "CLOSE"
    LISTEN = "LISTEN"


@dataclass
class ConntrackerEvent:
    """Event reported by conntrack"""

    event_type: Optional[EventType] = None
    five_tuple: FiveTuple = field(default_factory=FiveTuple)
    tcp_state: Optional[TcpState] = None


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


def parse_input(input_string) -> ConntrackerEvent:
    event = ConntrackerEvent()

    print(datetime.now(), "Conntracker reported event:", input_string)
    match = re.search(r"\[([A-Z]+)\] (\w+)", input_string)
    if match:
        event.event_type = EventType(match.group(1))
        protocol = match.group(2)

        if protocol == "icmp":
            if "type=0" in input_string or "type=8" in input_string:
                event.five_tuple.protocol = protocol
        elif protocol == "icmpv6":
            if "type=128" in input_string or "type=129" in input_string:
                event.five_tuple.protocol = protocol
        else:
            event.five_tuple.protocol = protocol

        if protocol == "tcp":
            match = re.search(r"tcp\s+[\d+ ]+([A-Z_]+)", input_string)
            if match:
                event.tcp_state = TcpState(match.group(1))

    match = re.search(r"src=([^\s]+)", input_string)
    if match:
        event.five_tuple.src_ip = match.group(1)

    match = re.search(r"dst=([^\s]+)", input_string)
    if match:
        event.five_tuple.dst_ip = match.group(1)

    match = re.search(r"sport=(\d+)", input_string)
    if match:
        event.five_tuple.src_port = int(match.group(1))

    match = re.search(r"dport=(\d+)", input_string)
    if match:
        event.five_tuple.dst_port = int(match.group(1))

    return event


class ConnectionTracker:
    def __init__(
        self,
        connection: Connection,
        configuration: Optional[List[ConnectionTrackerConfig]] = None,
        process_update_events: bool = False,
    ):
        args = ["conntrack", "-E", "-e", "NEW"]
        if process_update_events:
            args.extend(["-e", "UPDATES"])
        self._process: Process = connection.create_process(args)
        self._connection: Connection = connection
        self._process_update_events = process_update_events
        self._config: Optional[List[ConnectionTrackerConfig]] = configuration
        self._events: List[ConntrackerEvent] = []
        self._tcp_state_events: Dict[TcpState, List[asyncio.Event]] = defaultdict(list)
        self._sync_event: asyncio.Event = asyncio.Event()
        self._sync_connection: FiveTuple = FiveTuple(
            protocol="icmp", dst_ip="127.0.0.2"
        )

    async def on_stdout(self, stdout: str) -> None:
        if not self._config:
            return

        for line in stdout.splitlines():
            event = parse_input(line)
            connection = event.five_tuple
            if connection is FiveTuple():
                continue

            if self._sync_connection.partial_eq(connection):
                if not self._sync_event.is_set():
                    self._sync_event.set()
                # always skip events from sync_connection
                continue

            # skip if we are only interested in new events
            if not self._process_update_events and event.event_type != EventType.NEW:
                continue

            matching_configs = [
                cfg for cfg in self._config if cfg.target.partial_eq(connection)
            ]
            if not matching_configs:
                continue

            self._events.append(event)
            self._check_tcp_state_for_events(event)

    async def execute(self) -> None:
        if platform.system() == "Darwin":
            return None
        if not self._config:
            return None

        await self._process.execute(stdout_callback=self.on_stdout)

    def notify_on_tcp_state(self, state: TcpState, event: asyncio.Event) -> None:
        """Register an Event to be notified when a specific TCP state is reported"""
        self._tcp_state_events[state].append(event)

    async def get_out_of_limits(self) -> Optional[Dict[str, int]]:
        if platform.system() == "Darwin":
            return None
        if not self._config:
            return None

        await self._synchronize()

        out_of_limit_connections: Dict[str, int] = {}

        for cfg in self._config:
            count = len([
                event
                for event in self._events
                if cfg.target.partial_eq(event.five_tuple)
            ])
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

    def _check_tcp_state_for_events(self, conntracker_event: ConntrackerEvent) -> None:
        if tcp_state := conntracker_event.tcp_state:
            try:
                self._tcp_state_events[tcp_state].pop(0).set()
            except IndexError:
                pass

    async def _synchronize(self) -> None:
        if not self._config:
            return None

        print(datetime.now(), "ConnectionTracker waiting for _sync_event")
        # wait to synchronize over a known event
        while not self._sync_event.is_set():
            # use ping helper, that returns after the first reply is received
            await ping(self._connection, "127.0.0.2")

        self._sync_event.clear()

    @asynccontextmanager
    async def run(self) -> AsyncIterator["ConnectionTracker"]:
        async with self._process.run(stdout_callback=self.on_stdout):
            await self._process.wait_stdin_ready()

            # initialization is just waiting for first conntrack event
            await self._synchronize()
            yield self
