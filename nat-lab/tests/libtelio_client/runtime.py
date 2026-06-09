import asyncio
import time
from itertools import groupby
from tests.uniffi import VpnConnectionError
from tests.utils.bindings import (
    ErrorEvent,
    Event,
    LinkState,
    NodeState,
    PathType,
    RelayState,
    Server,
    TelioNode,
)
from tests.utils.output_notifier import OutputNotifier
from typing import List, Optional, Set, Tuple


class WontHappenError(Exception):
    pass


class Runtime:
    _output_notifier: OutputNotifier
    _peer_state_events: List[Tuple[float, TelioNode]]
    _derp_state_events: List[Server]
    _error_events: List[ErrorEvent]
    _started_tasks: List[str]
    _stopped_tasks: List[str]
    allowed_pub_keys: Set[str]

    def __init__(self) -> None:
        self._output_notifier = OutputNotifier()
        self._peer_state_events = []
        self._derp_state_events = []
        self._error_events = []
        self._started_tasks = []
        self._stopped_tasks = []
        self.allowed_pub_keys = set()

    async def handle_output_line(self, line) -> bool:
        return await self._output_notifier.handle_output(
            line
        ) or self._handle_task_information(line)

    def _handle_task_information(self, line) -> bool:
        if line.startswith("task started - "):
            tokens = line.split("task started - ")
            self._started_tasks.append(tokens[1].strip())
            return True

        if line.startswith("task stopped - "):
            tokens = line.split("task stopped - ")
            self._stopped_tasks.append(tokens[1].strip())
            return True

        return False

    def handle_event(self, event: Event, timestamp: float):
        if isinstance(event, Event.NODE):
            self._handle_node_event(event.body, timestamp)
        elif isinstance(event, Event.RELAY):
            self._handle_derp_event(event.body)
        elif isinstance(event, Event.ERROR):
            self._handle_error_event(event.body)
        else:
            raise TypeError(f"Got invalid event type: {event}")

    def _handle_node_event(self, node_event: TelioNode, timestamp: float):
        assert node_event.is_exit or (
            "0.0.0.0/0" not in node_event.allowed_ips
            and "::/0" not in node_event.allowed_ips
        )
        self.set_peer(node_event, timestamp)

    def _handle_derp_event(self, server: Server):
        self.set_derp(server)

    def _handle_error_event(self, error_event: ErrorEvent):
        self._error_events.append(error_event)

    def get_output_notifier(self) -> OutputNotifier:
        return self._output_notifier

    @staticmethod
    def _peer_state_matches(
        peer: Optional[TelioNode],
        states: List[NodeState],
        paths: List[PathType],
        is_exit: bool,
        is_vpn: bool,
        link_state: Optional[LinkState],
        vpn_connection_error: Optional[VpnConnectionError],
    ) -> bool:
        if peer is None:
            return False
        link_state_ok = link_state is None or peer.link_state == link_state
        vpn_error_ok = (
            vpn_connection_error is None
            or peer.vpn_connection_error == vpn_connection_error
        )
        return (
            peer.path in paths
            and peer.state in states
            and is_exit == peer.is_exit
            and is_vpn == peer.is_vpn
            and link_state_ok
            and vpn_error_ok
        )

    async def notify_peer_state(
        self,
        public_key: str,
        states: List[NodeState],
        paths: List[PathType],
        is_exit: bool = False,
        is_vpn: bool = False,
        link_state: Optional[LinkState] = None,
        vpn_connection_error: Optional[VpnConnectionError] = None,
    ) -> None:
        while True:
            peer = self.get_peer_info(public_key)
            if self._peer_state_matches(
                peer, states, paths, is_exit, is_vpn, link_state, vpn_connection_error
            ):
                return
            await asyncio.sleep(0.1)

    async def notify_link_state(self, public_key: str, state: LinkState) -> None:
        """Wait until a link_state event matching the `state` for `public_key` is available."""
        while True:
            peer = self.get_peer_info(public_key)
            if peer and peer.link_state == state:
                return
            await asyncio.sleep(0.1)

    async def notify_peer_event(
        self,
        public_key: str,
        states: List[NodeState],
        paths: List[PathType],
        is_exit: bool = False,
        is_vpn: bool = False,
        link_state: Optional[LinkState] = None,
    ) -> None:
        def _get_events() -> List[TelioNode]:
            return [
                peer
                for (ts, peer) in self._peer_state_events
                if peer
                and peer.public_key == public_key
                and peer.path in paths
                and peer.state in states
                and is_exit == peer.is_exit
                and is_vpn == peer.is_vpn
                and (link_state is None or peer.link_state == link_state)
            ]

        old_events = _get_events()

        while True:
            new_events = _get_events()[len(old_events) :]
            if new_events:
                return
            await asyncio.sleep(0.1)

    async def notify_peer_event_in_duration(
        self,
        public_key: str,
        states: List[NodeState],
        duration_from_now: float,
        paths: List[PathType],
        is_exit: bool = False,
        is_vpn: bool = False,
    ) -> None:
        now = time.time()
        deadline = now + duration_from_now

        def is_within_duration(ts):
            return ts <= deadline

        def is_matching(peer):
            return (
                peer
                and peer.public_key == public_key
                and peer.path in paths
                and peer.state in states
                and is_exit == peer.is_exit
                and is_vpn == peer.is_vpn
            )

        def _get_events() -> List[Tuple[float, TelioNode]]:
            ret = [
                (ts, peer)
                for (ts, peer) in self._peer_state_events
                if is_within_duration(ts) and is_matching(peer)
            ]
            if len(ret) == 0:
                if [ts for (ts, peer) in self._peer_state_events if (deadline) < ts]:
                    # We got an (non matching) event which is later than the deadline, so
                    # there is no chance that we will get any new events from before the deadline.
                    raise WontHappenError()
            return ret

        old_events = _get_events()

        while True:
            new_events = _get_events()[len(old_events) :]
            if new_events:
                return
            await asyncio.sleep(0.1)

    def get_link_state_events(self, public_key: str) -> List[LinkState]:
        raw_states = [
            peer.link_state
            for (ts, peer) in self._peer_state_events
            if peer and peer.public_key == public_key and peer.link_state is not None
        ]
        # This removes consecutive UP events (connecting + connected)
        deduplicated = [state for state, _ in groupby(raw_states)]
        return deduplicated

    def get_peer_info(self, public_key: str) -> Optional[TelioNode]:
        events = [
            peer_event
            for (ts, peer_event) in self._peer_state_events
            if peer_event.public_key == public_key
        ]
        if events:
            return events[-1]
        return None

    async def notify_derp_state(
        self,
        server_ip: str,
        states: List[RelayState],
    ) -> None:
        while True:
            derp = self.get_derp_info(server_ip)
            if derp and derp.ipv4 == server_ip and derp.conn_state in states:
                return
            await asyncio.sleep(0.1)

    async def notify_derp_event(
        self,
        server_ip: str,
        states: List[RelayState],
    ) -> None:
        def _get_events() -> List[Server]:
            return [
                event
                for event in self._derp_state_events
                if event.ipv4 == server_ip and event.conn_state in states
            ]

        old_events = _get_events()

        while True:
            new_events = _get_events()[len(old_events) :]
            if new_events:
                return
            await asyncio.sleep(0.1)

    def get_derp_info(self, server_ip: str) -> Optional[Server]:
        events = [event for event in self._derp_state_events if event.ipv4 == server_ip]
        if events:
            return events[-1]
        return None

    def set_peer(self, peer: TelioNode, timestamp: float) -> None:
        assert peer.public_key in self.allowed_pub_keys
        self._peer_state_events.append((timestamp, peer))

    def set_derp(self, derp: Server) -> None:
        self._derp_state_events.append(derp)

    def get_started_tasks(self) -> List[str]:
        return self._started_tasks

    def get_stopped_tasks(self) -> List[str]:
        return self._stopped_tasks

    async def notify_error_event(self, err: ErrorEvent) -> None:
        def _get_events() -> List[ErrorEvent]:
            return [error for error in self._error_events if error == err]

        old_events = _get_events()
        while True:
            new_events = _get_events()[len(old_events) :]
            if new_events:
                return
            await asyncio.sleep(0.1)


class Events:
    _runtime: Runtime

    def __init__(
        self,
        runtime: Runtime,
    ) -> None:
        self._runtime = runtime

    async def wait_for_state_peer(
        self,
        public_key: str,
        state: List[NodeState],
        paths: List[PathType],
        is_exit: bool = False,
        is_vpn: bool = False,
        timeout: Optional[float] = None,
        link_state: Optional[LinkState] = None,
        vpn_connection_error: Optional[VpnConnectionError] = None,
    ) -> None:
        await asyncio.wait_for(
            self._runtime.notify_peer_state(
                public_key,
                state,
                paths,
                is_exit,
                is_vpn,
                link_state,
                vpn_connection_error,
            ),
            timeout,
        )

    async def wait_for_link_state(
        self,
        public_key: str,
        state: LinkState,
        timeout: Optional[float] = None,
    ) -> None:
        """Wait until a link_state event matching the `state` for `public_key` is available."""
        await asyncio.wait_for(
            self._runtime.notify_link_state(public_key, state), timeout
        )

    async def wait_for_event_peer(
        self,
        public_key: str,
        states: List[NodeState],
        paths: List[PathType],
        is_exit: bool = False,
        is_vpn: bool = False,
        timeout: Optional[float] = None,
        link_state: Optional[LinkState] = None,
    ) -> None:
        await asyncio.wait_for(
            self._runtime.notify_peer_event(
                public_key, states, paths, is_exit, is_vpn, link_state
            ),
            timeout,
        )

    async def wait_for_future_event_peer(
        self,
        public_key: str,
        states: List[NodeState],
        duration_from_now: float,
        paths: List[PathType],
        is_exit: bool = False,
        is_vpn: bool = False,
    ) -> None:
        await self._runtime.notify_peer_event_in_duration(
            public_key, states, duration_from_now, paths, is_exit, is_vpn
        )

    def get_link_state_events(self, public_key: str) -> List[LinkState]:
        return self._runtime.get_link_state_events(public_key)

    async def wait_for_state_derp(
        self, server_ip: str, states: List[RelayState], timeout: Optional[float] = None
    ) -> None:
        await asyncio.wait_for(
            self._runtime.notify_derp_state(server_ip, states), timeout
        )

    async def wait_for_event_derp(
        self, server_ip: str, states: List[RelayState], timeout: Optional[float] = None
    ) -> None:
        await asyncio.wait_for(
            self._runtime.notify_derp_event(server_ip, states), timeout
        )

    async def wait_for_event_error(
        self, err: ErrorEvent, timeout: Optional[float] = None
    ) -> None:
        await asyncio.wait_for(self._runtime.notify_error_event(err), timeout)
