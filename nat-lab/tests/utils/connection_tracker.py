import asyncio
import platform
import re
from collections import defaultdict
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from enum import Enum
from tests.utils.connection import Connection
from tests.utils.connection.ssh_connection import SshConnection
from tests.utils.logger import log
from tests.utils.ping import ping
from tests.utils.process import Process
from typing import Optional, List, Dict, AsyncIterator

NEXT_CONNTRACKER_ID = 0


@dataclass
class FiveTuple:
    """
    Represents a connection identified by its protocol, source and destination

    Any part of the tuple may be skipped in matching the connection, hence it allows
    for some primitive host or destination matching
    """

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

    def __hash__(self):
        return hash(
            (self.protocol, self.src_ip, self.dst_ip, self.src_port, self.dst_port)
        )

    def __str__(self) -> str:
        return f"{self.protocol} {self.src_ip}:{self.src_port} -> {self.dst_ip}:{self.dst_port}"


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


@dataclass()
class ConnTrackerViolation:
    """
    Represents whether it is possible, the result will become valid in the future
    For example if connection count is currently lower than minimal results, it is
    possible that program under test will create one, and result will become valid.
    On the other hand - if we are already over limit - we will never be able to recover.

    This is useful when waiting for valid conntracker state. Conntracker will stop waiting
    once at least one validator returns non-recoverable invalid result.
    """

    recoverable: bool

    """
    This field is designated for debugging efforts, and should specify human-readable details about
    validation result, especially if validation failed.
    """
    reason: str


def merge_results(
    results: list[Optional[ConnTrackerViolation]],
) -> Optional[ConnTrackerViolation]:
    violations = list(filter(lambda r: r is not None, results))
    if len(violations) == 0:
        return None

    if len(violations) == 1:
        return violations[0]

    # Need to merge all violations into single validation result
    reason = (
        f"There are {len(violations)} violations of conntracker events expectations:\n"
    )
    reason += "\n  ".join([v.reason for v in violations if v])

    recoverable = all(v is None or v.recoverable is True for v in violations)

    return ConnTrackerViolation(recoverable, reason)


@dataclass
class ConntrackerEvent:
    """Event reported by conntrack"""

    event_type: Optional[EventType] = None
    five_tuple: FiveTuple = field(default_factory=FiveTuple)
    tcp_state: Optional[TcpState] = None


class ConnTrackerEventsValidator:
    """
    Generic class for representing conntracker events validator
    """

    def find_conntracker_violations(
        self, _: List[ConntrackerEvent]
    ) -> Optional[ConnTrackerViolation]:
        raise NotImplementedError("Not implemented error")


class ConnectionCountLimit(ConnTrackerEventsValidator):
    """
    Connection validator which checks whether number of connections matching provided Five Tuple (note that five tuple many
    specify only subset of elements, e.g. skipping source or destination) is within range.
    """

    @classmethod
    def create_with_tuple(
        cls, key: str, limits: tuple[Optional[int], Optional[int]], target: FiveTuple
    ):
        return cls(key, target, limits[0], limits[1])

    def __init__(
        self,
        key: str,
        target: FiveTuple,
        min_limit: Optional[int] = None,
        max_limit: Optional[int] = None,
    ):
        if max_limit is not None and min_limit is not None and max_limit < min_limit:
            raise ValueError(
                f"Max limit {max_limit} is smaller than min limit {min_limit}"
            )

        self.key = key
        self.min_limit = min_limit
        self.max_limit = max_limit
        self.target = target

    def __repr__(self):
        return f"ConnectionCountLimit(key: {self.key}, min_limit: {self.min_limit}, max_limit: {self.max_limit}, target: {self.target})"

    def find_conntracker_violations(
        self, events: List[ConntrackerEvent]
    ) -> Optional[ConnTrackerViolation]:
        # We would like to return all connections, which are out of limits
        # Instead of just first one which happens to be in the list.

        # Count connections matching our five tuple
        count = len([
            event
            for event in events
            if event.event_type == EventType.NEW
            and self.target.partial_eq(event.five_tuple)
        ])

        if self.max_limit is not None and count > self.max_limit:
            return ConnTrackerViolation(
                recoverable=False,
                reason=f"In {self.key} there has been {count} connections; filter: {self.target}; violated max connection limit: {self.max_limit}; conntracker events: {events}",
            )
        if self.min_limit is not None and count < self.min_limit:
            return ConnTrackerViolation(
                recoverable=True,
                reason=f"In {self.key} there has been {count} connections; filter: {self.target}; violated min connection limit: {self.min_limit}; conntracker events: {events}",
            )

        return None


class TCPStateSequence(ConnTrackerEventsValidator):
    """
    Conntracker events validator which ensures all connections matching FiveTuple has gone through specific sequence of TCP state transitions

    Note this validator allows for various TCP states on connections, but full sequence of states must *end* in specified sequence.
    """

    def __init__(
        self,
        key: str,
        five_tuple: FiveTuple,
        sequence: List[TcpState],
        trailing_state: Optional[TcpState] = None,
    ):
        if five_tuple.protocol is None or five_tuple.protocol != "tcp":
            raise ValueError(
                'TcpStateSequence validator is only available for "tcp" protocol five tuples'
            )

        if len(sequence) == 0:
            raise ValueError(
                "TcpStateSequence validator is noop when requested sequence is empty"
            )

        self.key = key
        self.five_tuple = five_tuple
        self.sequence = sequence
        self.trailing_state = trailing_state

    def __repr__(self):
        return f"TCPStateSequence(key: {self.key}, five_tuple: {self.five_tuple}, sequence: {self.sequence})"

    def find_conntracker_violations(
        self, events: List[ConntrackerEvent]
    ) -> Optional[ConnTrackerViolation]:
        # First we need to build a list of distinct connections matching FiveTuple

        # There is this quirk, that conntracker events are distributed over time
        # which means, that same FiveTuple can represent multiple connections which
        # are non-overlapping in time. We need to handle it.
        #
        # Ultimately we are building two dimensional list here, where first level
        # is representing distinct connections, and second level ConnTrackerEvent's
        # belonging to each connection. So later we can analyze sequences of events
        # more easily.
        # We can exploit the fact that those connections reusing the same FiveTuple
        # cannot overlap in time and events list is sorted by time. For this reason
        # connection cache is introduced which maps FiveTuple to index in two dimensional
        # array, and gets cleared every time NEW type event appears in the list of events
        connections: Dict[FiveTuple, List[List[ConntrackerEvent]]] = {}
        for event in filter(lambda e: self.five_tuple.partial_eq(e.five_tuple), events):
            # Every new connection (identified by EventType NEW) gets its own slot
            ft = event.five_tuple
            if event.event_type == EventType.NEW:
                connections[ft] = (
                    [[]] if ft not in connections else (connections[ft] + [[]])
                )

            # append event
            connections[ft][-1].append(event)

        # Flatten one level, as we have five_tuple -> connection -> events, and
        # Sequence validation requires connection -> events
        sequences = [
            event for connection in connections.values() for event in connection
        ]

        # Verify whether all conections end up with expected sequence of TCP states
        violations: list[Optional[ConnTrackerViolation]] = []
        for connection in sequences:
            if self.trailing_state == connection[-1].tcp_state:
                # Skip the trailing tcp state
                state_sequence = list(map(lambda c: c.tcp_state, connection))[
                    -len(self.sequence) - 1 : -1
                ]
            else:
                state_sequence = list(map(lambda c: c.tcp_state, connection))[
                    -len(self.sequence) :
                ]

            if state_sequence != self.sequence:
                violations.append(
                    ConnTrackerViolation(
                        recoverable=True,
                        reason=f"In {self.key} connection {connection[0].five_tuple} has mismatching TCP state sequence. Expected: {self.sequence}, have: {state_sequence}",
                    )
                )

        return merge_results(violations)


def parse_input(
    input_string, contracker_id: int, container_name: Optional[str] = None
) -> ConntrackerEvent:
    event = ConntrackerEvent()

    if container_name:
        log.debug(
            "[%s] Conntracker[%s] reported event: %s",
            container_name,
            contracker_id,
            input_string,
        )
    else:
        log.debug("Conntracker reported event: %s", input_string)

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
        validators: Optional[List[ConnTrackerEventsValidator]] = None,
    ):
        global NEXT_CONNTRACKER_ID
        self.id: int = NEXT_CONNTRACKER_ID + 1
        NEXT_CONNTRACKER_ID += 1

        log.debug(
            "ConnectionTracker[%s] starting with validators: %s", self.id, validators
        )

        args = ["conntrack", "-E"]
        self._process: Process = connection.create_process(
            args,
            term_type=("xterm" if isinstance(connection, SshConnection) else None),
            quiet=True,
        )
        self._connection: Connection = connection
        self._validators: Optional[List[ConnTrackerEventsValidator]] = validators
        self._events: List[ConntrackerEvent] = []
        self._tcp_state_events: Dict[TcpState, List[asyncio.Event]] = defaultdict(list)
        self._sync_event: asyncio.Event = asyncio.Event()
        self._sync_connection: FiveTuple = FiveTuple(
            protocol="icmp", dst_ip="127.0.0.2"
        )
        self._new_report_event = asyncio.Event()

    async def on_stdout(self, stdout: str) -> None:
        if not self._validators:
            return

        for line in stdout.splitlines():
            event = parse_input(line, self.id, self._connection.tag.name)
            connection = event.five_tuple
            if connection is FiveTuple():
                continue

            if self._sync_connection.partial_eq(connection):
                if not self._sync_event.is_set():
                    self._sync_event.set()
                # always skip events from sync_connection
                continue

            self._events.append(event)
            self._new_report_event.set()

    async def execute(self) -> None:
        if platform.system() == "Darwin":
            return None
        if not self._validators:
            return None

        await self._process.execute(stdout_callback=self.on_stdout)

    def notify_on_tcp_state(self, state: TcpState, event: asyncio.Event) -> None:
        """Register an Event to be notified when a specific TCP state is reported"""
        self._tcp_state_events[state].append(event)

    async def find_conntracker_violations(self) -> Optional[ConnTrackerViolation]:
        if platform.system() == "Darwin":
            return None
        if not self._validators:
            return None

        await self._synchronize()

        return merge_results(
            [v.find_conntracker_violations(self._events) for v in self._validators]
        )

    async def wait_for_no_violations(self):
        """Waits until there are no conntracker event violations. If unrecoverable event occures throws"""
        # The implementation is polling, which is probably not super efficient, but at least simple :)
        while True:
            await self._new_report_event.wait()
            self._new_report_event.clear()

            violation = await self.find_conntracker_violations()
            if violation is None:
                break

            if not violation.recoverable:
                raise Exception(violation)
            log.debug(
                "ConnectionTracker[%s] recoverable violation: %s",
                self.id,
                violation,
            )

    async def _synchronize(self) -> None:
        if not self._validators:
            return None

        log.debug("ConnectionTracker[%s] waiting for _sync_event (ping)", self.id)
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
