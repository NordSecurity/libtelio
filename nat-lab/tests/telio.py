# pylint: disable=too-many-lines
import asyncio
import platform
import re
import time
import uuid
from collections import Counter
from contextlib import AsyncExitStack, asynccontextmanager
from datetime import datetime
from itertools import groupby
from tests.config import DERP_SERVERS
from tests.log_collector import (
    LOG_COLLECTORS,
    LogCollector,
    clear_core_dumps,
    get_log_without_flush,
)
from tests.mesh_api import Node
from tests.uniffi import VpnConnectionError
from tests.uniffi.libtelio_proxy import LibtelioProxy, ProxyConnectionError
from tests.utils import asyncio_util
from tests.utils.bindings import (
    Config,
    ErrorEvent,
    Event,
    Features,
    LinkState,
    NodeState,
    PathType,
    RelayState,
    Server,
    TelioAdapterType,
    TelioNode,
    default_features,
)
from tests.utils.command_grepper import CommandGrepper
from tests.utils.connection import Connection, TargetOS
from tests.utils.connection.docker_connection import DockerConnection
from tests.utils.connection_util import get_uniffi_path
from tests.utils.logger import log
from tests.utils.moose import MOOSE_DB_TIMEOUT_MS
from tests.utils.output_notifier import OutputNotifier
from tests.utils.perf_profiling import PERF_CMD, PerfProfiler
from tests.utils.process import Process
from tests.utils.python import get_python_binary
from tests.utils.router import IPStack, Router, new_router
from tests.utils.router.linux_router import (
    FWMARK_VALUE as LINUX_FWMARK_VALUE,
    LinuxRouter,
)
from tests.utils.router.windows_router import WindowsRouter
from tests.utils.tcpdump import make_tcpdump
from typing import AsyncIterator, List, Optional, Set, Tuple

DEVICE_STOP_TIMEOUT = 30


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
            if (
                peer
                and peer.path in paths
                and peer.state in states
                and is_exit == peer.is_exit
                and is_vpn == peer.is_vpn
                and (link_state is None or peer.link_state == link_state)
                and (
                    vpn_connection_error is None
                    or peer.vpn_connection_error == vpn_connection_error
                )
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


class Client:
    def __init__(
        self,
        connection: Connection,
        node: Node,
        adapter_type: Optional[TelioAdapterType] = None,
        telio_features: Features = default_features(),
        force_ipv6_feature: bool = False,
        fingerprint: str = "",
    ) -> None:
        self._events: Optional[Events] = None
        self._runtime: Optional[Runtime] = None
        self._process: Optional[Process] = None
        self._interface_configured = False
        self._message_idx = 0
        self._node = node
        self._connection = connection
        self._router: Router = new_router(self._connection, self._node.ip_stack)
        # If the passed adapter_type is None, use the default for the given OS
        # At the time of writing this comment, that means:
        #   Windows -> WindowsNativeWG
        #   All other platforms -> NepTUN
        if adapter_type is not None:
            self._adapter_type = adapter_type
        elif isinstance(self.get_router(), WindowsRouter):
            self._adapter_type = TelioAdapterType.WINDOWS_NATIVE_TUN
        else:
            self._adapter_type = TelioAdapterType.NEP_TUN
        self._telio_features = telio_features
        self._quit = False
        self._start_time = datetime.now()
        self._libtelio_proxy: Optional[LibtelioProxy] = None
        self._proxy_port = ""
        self._fingerprint: Optional[tuple[str, str]] = None
        self._allowed_errors: Optional[List[re.Pattern]] = None
        # Automatically enables IPv6 feature when the IPv6 stack is enabled
        if (
            self._node.ip_stack in (IPStack.IPv4v6, IPStack.IPv6)
            and not force_ipv6_feature
        ):
            self._telio_features.ipv6 = True
        if telio_features.nurse is not None and telio_features.lana is not None:
            self._fingerprint = telio_features.lana.event_path, fingerprint

    def is_node(self, node: Node) -> bool:
        return self._node == node

    def get_connection(self):
        return self._connection

    def get_proxy_port(self):
        return self._proxy_port

    @property
    def node(self) -> Node:
        return self._node

    @asynccontextmanager
    async def run(
        self,
        meshnet_config: Optional[Config] = None,
        run_tcpdump: Optional[bool] = True,
        enable_perf: Optional[bool] = False,
    ) -> AsyncIterator["Client"]:
        async def on_stdout(stdout: str) -> None:
            supress_print_list = [
                "- no login.",
                "- telio running.",
                "- telio nodes",
                "task stopped - ",
                "task started - ",
            ]
            for line in stdout.splitlines():
                if line.startswith("libtelio-port:"):
                    self._proxy_port = line[len("libtelio-port:") :]
                if not any(string in line for string in supress_print_list):
                    log.info("[%s] stdout: %s", self._node.name, line)
                if self._runtime:
                    await self._runtime.handle_output_line(line)

        async def on_stderr(stderr: str) -> None:
            for line in stderr.splitlines():
                log.error("[%s] stderr: %s", self._node.name, line)
                if self._runtime:
                    await self._runtime.handle_output_line(line)

        self._runtime = Runtime()
        self._events = Events(self._runtime)

        object_name = str(uuid.uuid4()).replace("-", "")
        (host_ip, container_ip) = await self._connection.get_ip_address()

        host_os = platform.system()
        if host_os == "Linux":
            host_ip = container_ip
        (host_port, container_port) = await self._connection.mapped_ports()

        python_cmd = get_python_binary(self._connection)
        uniffi_path = get_uniffi_path(self._connection)
        base_cmd = [
            python_cmd,
            uniffi_path,
            object_name,
            container_ip,
            container_port,
        ]
        if enable_perf:
            cmd = PERF_CMD + base_cmd
        else:
            cmd = base_cmd

        self._process = self._connection.create_process(
            cmd,
            quiet=True,
        )

        async with AsyncExitStack() as exit_stack:
            if enable_perf:
                await exit_stack.enter_async_context(
                    PerfProfiler(connection=self._connection)
                )
            if run_tcpdump:
                await exit_stack.enter_async_context(make_tcpdump([self._connection]))
            if isinstance(self._connection, DockerConnection):
                await clear_core_dumps(self._connection)

            await self.clear_system_log()

            await exit_stack.enter_async_context(
                self._process.run(stdout_callback=on_stdout, stderr_callback=on_stderr)
            )
            try:
                await self._process.wait_stdin_ready()

                # There are two scenarios when it comes to what port is being used to connect to the Pyro5 remote.
                # Scenario 1 - docker with mapped ports:
                #   In this case we just use the mapped ports.
                #   We get this from docker_connection#mapped_ports by inspecting the container
                # Scenario 2 - non-docker scenarios or docker without mapped ports (like in our CI):
                #   Natlab can run clients in mac and windows VMs, not just in docker containers, and in some scenarios, like our CI,
                #   we can't currently use mapped ports. In those cases we let Pyro5 select a port on its own (by giving it 0 as the port number).
                #   libtelio_remote prints what port was used after binding and we collect it here in self._proxy_port
                if host_port == "0":
                    while len(self._proxy_port) == 0 and self._process.is_executing():
                        await asyncio.sleep(0.25)
                    object_uri = f"PYRO:{object_name}@{host_ip}:{self._proxy_port}"
                else:
                    object_uri = f"PYRO:{object_name}@localhost:{host_port}"

                self._libtelio_proxy = LibtelioProxy(object_uri, self._telio_features)
                try:
                    await self.get_proxy().create()
                except ProxyConnectionError as err:
                    log.error(str(err))
                    raise err

                await self.maybe_write_device_fingerprint_to_moose_db()

                await self.get_proxy().start_named(
                    private_key=self._node.private_key,
                    adapter=self._adapter_type,
                    name=self.get_router().get_interface_name(),
                )

                if isinstance(self.get_router(), LinuxRouter):
                    await self.get_proxy().set_fwmark(int(LINUX_FWMARK_VALUE))

                async with asyncio_util.run_async_context(self._event_request_loop()):
                    if meshnet_config:
                        await self.set_meshnet_config(meshnet_config)
                    log_collector = LogCollector(self)
                    LOG_COLLECTORS.append(log_collector)
                    yield self
            finally:
                await self.cleanup()

    async def cleanup(self):
        assert self._process

        stop_exception = None

        log.info(
            "[%s] Test cleanup: Stopping device",
            self._node.name,
        )
        if self._process.is_executing():
            log.info(
                "[%s] Test cleanup: process is still executing",
                self._node.name,
            )
            if self._libtelio_proxy:
                log.info(
                    "[%s] Test cleanup: will stop the device",
                    self._node.name,
                )
                try:
                    async with asyncio.timeout(DEVICE_STOP_TIMEOUT):
                        await self.stop_device()
                        self._quit = True
                # pylint: disable=broad-except
                except Exception as e:
                    log.exception(
                        "[%s] Exception while stopping device: %s. Will ignore until the end of the cleanup",
                        self._node.name,
                        e,
                    )
                    stop_exception = e
            else:
                log.info(
                    "[%s] Test cleanup: We don't have LibtelioProxy instance, Stop() not called.",
                    self._node.name,
                )

        log.info("[%s]  Test cleanup: Shutting down", self._node.name)
        if self._libtelio_proxy:
            # flush_logs() is allowed to fail here:
            try:
                await self.get_proxy().flush_logs()
            # Since this is clean up code, catching general exceptions is fine:
            except Exception as e:  # pylint: disable=broad-exception-caught
                log.info(
                    "[%s] Test cleanup: Exception while flushing logs: %s",
                    self._node.name,
                    e,
                )

            await self.get_proxy().shutdown(self._connection.tag.name)
        else:
            log.info(
                "[%s] We don't have LibtelioProxy instance, Shutdown() not called.",
                self._node.name,
            )

        log.info("[%s] Test cleanup: Clearing up routes", self._node.name)
        await self._router.delete_vpn_route()
        await self._router.delete_exit_node_route()
        await self._router.delete_interface()

        log.info("[%s] Test cleanup complete", self._node.name)
        if stop_exception is not None:
            raise stop_exception

    async def simple_start(self):
        await self.get_proxy().start_named(
            private_key=self._node.private_key,
            adapter=self._adapter_type,
            name=self.get_router().get_interface_name(),
        )
        if isinstance(self.get_router(), LinuxRouter):
            await self.get_proxy().set_fwmark(int(LINUX_FWMARK_VALUE))

    async def create_tun(self, tun_id: int) -> int:
        return await self.get_proxy().create_tun(tun_id)

    async def start_with_tun(self, tun: int, tun_name):
        await self.get_proxy().start_with_tun(
            private_key=self._node.private_key,
            adapter=self._adapter_type,
            tun=tun,
        )
        if isinstance(self.get_router(), LinuxRouter):
            self.get_router().set_interface_name(tun_name)
            await self.get_proxy().set_fwmark(int(LINUX_FWMARK_VALUE))

    async def start_named_ext_if_filter(self, tun_name, ext_if_filter: List[str]):
        if not isinstance(self.get_router(), WindowsRouter):
            raise Exception("start_named_ext_if_filter can only be used on Windows")
        await self.get_proxy().start_named_ext_if_filter(
            private_key=self._node.private_key,
            adapter=self._adapter_type,
            name=tun_name,
            ext_if_list=ext_if_filter,
        )

    async def wait_for_state_peer(
        self,
        public_key,
        states: List[NodeState],
        paths: Optional[List[PathType]] = None,
        is_exit: bool = False,
        is_vpn: bool = False,
        timeout: Optional[float] = None,
        link_state: Optional[LinkState] = None,
        vpn_connection_error: Optional[VpnConnectionError] = None,
    ) -> None:
        info = f"peer({public_key}) with states({states}), paths({paths}), is_exit({is_exit}), is_vpn({is_vpn}), link_state({link_state}), vpn_connection_error({vpn_connection_error})"

        log.debug("[%s]: wait for peer state %s", self._node.name, info)
        await self.get_events().wait_for_state_peer(
            public_key,
            states,
            paths if paths else [PathType.RELAY],
            is_exit,
            is_vpn,
            timeout,
            link_state,
            vpn_connection_error,
        )

    async def wait_for_link_state(
        self,
        public_key: str,
        state: LinkState,
        timeout: Optional[float] = None,
    ) -> None:
        """Wait until a link_state event matching the `state` for `public_key` is available."""
        info = f"peer({public_key}) with state({state})"

        log.debug("[%s]: wait for link state %s", self._node.name, info)
        await self.get_events().wait_for_link_state(
            public_key,
            state,
            timeout,
        )

    async def wait_for_event_peer(
        self,
        public_key: str,
        states: List[NodeState],
        paths: Optional[List[PathType]] = None,
        is_exit: bool = False,
        is_vpn: bool = False,
        timeout: Optional[float] = None,
        link_state: Optional[LinkState] = None,
    ) -> None:
        event_info = f"peer({public_key}) with states({states}), paths({paths}), link_state({link_state}), is_exit={is_exit}, is_vpn={is_vpn}"

        log.debug("[%s]: wait for peer event %s", self._node.name, event_info)
        await self.get_events().wait_for_event_peer(
            public_key,
            states,
            paths if paths else [PathType.RELAY],
            is_exit,
            is_vpn,
            timeout,
            link_state,
        )
        log.debug("[%s]: got peer event %s", self._node.name, event_info)

    async def wait_for_future_event_peer(
        self,
        public_key: str,
        states: List[NodeState],
        duration_from_now=float,
        paths: Optional[List[PathType]] = None,
        is_exit: bool = False,
        is_vpn: bool = False,
    ) -> None:
        """
        Wait for a matching event, until it occurs or throw an WontHappenError if it's guaranteed it will not happen.

        This method is useful to avoid problem related to transient netwroking issues which can delay events by few seconds.
        It uses the timestamps of events generated on the remote side where libtelio is located, instead of using the local
        time of receiving of event.
        """
        event_info = f"peer({public_key}) with states({states}), duration_from_now={duration_from_now}, paths({paths}), is_exit={is_exit}, is_vpn={is_vpn}"

        log.debug("[%s]: wait for peer event %s", self._node.name, event_info)
        await self.get_events().wait_for_future_event_peer(
            public_key,
            states,
            duration_from_now,
            paths if paths else [PathType.RELAY],
            is_exit,
            is_vpn,
        )
        log.debug("[%s]: got peer event %s", self._node.name, event_info)

    def get_link_state_events(self, public_key: str) -> List[LinkState]:
        return self.get_events().get_link_state_events(public_key)

    async def wait_for_state_derp(
        self, derp_ip, states: List[RelayState], timeout: Optional[float] = None
    ) -> None:
        await self.get_events().wait_for_state_derp(derp_ip, states, timeout)

    async def wait_for_state_on_any_derp(
        self, states: List[RelayState], timeout: Optional[float] = None
    ) -> None:
        async with asyncio_util.run_async_contexts([
            self.get_events().wait_for_state_derp(str(derp.ipv4), states, timeout)
            for derp in DERP_SERVERS
        ]) as futures:
            try:
                while not any(fut.done() for fut in futures):
                    await asyncio.sleep(0.01)
            except asyncio.CancelledError:
                pass

    async def wait_for_every_derp_disconnection(
        self, timeout: Optional[float] = None
    ) -> None:
        async with asyncio_util.run_async_contexts([
            self.get_events().wait_for_state_derp(
                str(derp.ipv4),
                [RelayState.DISCONNECTED, RelayState.CONNECTING],
                timeout,
            )
            for derp in DERP_SERVERS
        ]) as futures:
            try:
                while not all(fut.done() for fut in futures):
                    await asyncio.sleep(0.1)
            except asyncio.CancelledError:
                pass

    async def wait_for_event_derp(
        self, derp_ip, states: List[RelayState], timeout: Optional[float] = None
    ) -> None:
        event_info = f"derp({derp_ip}) with states({states})"

        log.debug("[%s]: wait for derp event %s", self._node.name, event_info)
        await self.get_events().wait_for_event_derp(derp_ip, states, timeout)
        log.debug("[%s]: got derp event %s", self._node.name, event_info)

    async def wait_for_event_on_any_derp(
        self, states: List[RelayState], timeout: Optional[float] = None
    ) -> None:
        async with asyncio_util.run_async_contexts([
            self.get_events().wait_for_event_derp(str(derp.ipv4), states, timeout)
            for derp in DERP_SERVERS
        ]) as futures:
            try:
                while not any(fut.done() for fut in futures):
                    await asyncio.sleep(0.1)
            except asyncio.CancelledError:
                pass

    async def wait_for_event_error(self, err: ErrorEvent):
        await self.get_events().wait_for_event_error(err)

    async def set_meshnet_config(self, meshnet_config: Config) -> None:
        made_changes = await self._configure_interface()

        # Linux native WG takes ~1.5s to setup listen port for WG interface. Since
        # listen port is required for mesh connection, there is no other way to
        # bypass this waiting period. Another option would be to retry `mesh config`
        # multiple times until the command succeeds.
        if made_changes and self._adapter_type == TelioAdapterType.LINUX_NATIVE_TUN:
            await asyncio.sleep(2)

        if meshnet_config.peers is not None:
            peer_pkeys = [peer.base.public_key for peer in meshnet_config.peers]
            for peer_pkey in peer_pkeys:
                self.get_runtime().allowed_pub_keys.add(peer_pkey)

        await self.get_proxy().set_meshnet(meshnet_config)

    async def set_mesh_off(self):
        await self.get_proxy().set_meshnet_off()

    async def receive_ping(self) -> str:
        return await self.get_proxy().receive_ping()

    async def wait_for_listen_port_ready(
        self,
        protocol: str,
        port: int,
        process: str = "python3",
        timeout: Optional[float] = None,
    ) -> None:
        assert (
            self._connection.target_os == TargetOS.Linux
        ), "Waiting for listen ports is supported only on Linux hosts"

        if not await CommandGrepper(
            self._connection,
            [
                "netstat",
                "-lpn",
            ],
            timeout,
        ).check_exists(f":{port} ", [protocol, process]):
            raise Exception("Listening socket could not be found")

    async def connect_to_vpn(
        self,
        ip: str,
        port: int,
        public_key: str,
        timeout: Optional[float] = None,
        pq: bool = False,
        link_state_enabled: bool = False,
    ) -> None:
        await self._configure_interface()
        await self.get_router().create_vpn_route()
        async with asyncio_util.run_async_context(
            self.wait_for_event_peer(
                public_key,
                [NodeState.CONNECTED],
                list(PathType),
                is_exit=True,
                is_vpn=True,
                timeout=timeout,
                link_state=LinkState.UP if link_state_enabled else None,
            )
        ) as event:
            self.get_runtime().allowed_pub_keys.add(public_key)

            if pq:
                await self.get_proxy().connect_to_exit_node_pq(
                    public_key=public_key,
                    allowed_ips=None,
                    endpoint=f"{ip}:{port}",
                )
            else:
                await self.get_proxy().connect_to_exit_node(
                    public_key=public_key,
                    allowed_ips=None,
                    endpoint=f"{ip}:{port}",
                )
            await event

    async def set_secret_key(self, secret_key: str):
        await self.get_proxy().set_secret_key(secret_key)

    async def disconnect_from_vpn(
        self,
        public_key: str,
        timeout: Optional[float] = None,
    ) -> None:
        async with asyncio_util.run_async_context(
            self.wait_for_event_peer(
                public_key,
                [NodeState.DISCONNECTED],
                list(PathType),
                is_exit=True,
                is_vpn=True,
                timeout=timeout,
            )
        ) as event:
            await self.get_proxy().disconnect_from_exit_nodes()
            await asyncio.gather(
                event,
                self.get_router().delete_vpn_route(),
            )

    async def disconnect_from_exit_node(
        self,
        public_key: str,
        timeout: Optional[float] = None,
    ) -> None:
        async with asyncio_util.run_async_context(
            self.wait_for_event_peer(
                public_key, [NodeState.CONNECTED], list(PathType), timeout=timeout
            )
        ) as event:
            await self.get_proxy().disconnect_from_exit_nodes()
            await asyncio.gather(
                event,
                self.get_router().delete_vpn_route(),
            )

    async def enable_magic_dns(self, forward_servers: List[str]) -> None:
        # Magic DNS required adapter port.
        # For the reasoning behind this see `set_meshnet_config()`
        configured = await self._configure_interface()
        if configured and self._adapter_type == TelioAdapterType.LINUX_NATIVE_TUN:
            await asyncio.sleep(2.0)

        await self.get_proxy().enable_magic_dns(forward_servers)

    async def disable_magic_dns(self) -> None:
        await self.get_proxy().disable_magic_dns()

    async def notify_network_change(self) -> None:
        await self.get_proxy().notify_network_change()

    async def _configure_interface(self) -> bool:
        if not self._interface_configured:
            await self.get_router().setup_interface(self._node.ip_addresses)

            await self.get_router().create_meshnet_route()
            self._interface_configured = True
            return True

        return False

    async def restart_interface(self, new_name=None):
        if self._interface_configured:
            await self.get_router().deconfigure_interface(self._node.ip_addresses)
            self._interface_configured = False
        if new_name:
            self.get_router().set_interface_name(new_name)
            self._interface_configured = False
        await self._configure_interface()

    async def connect_to_exit_node(
        self,
        public_key: str,
        timeout: Optional[float] = None,
    ) -> None:
        await self._configure_interface()
        await self.get_router().create_vpn_route()
        async with asyncio_util.run_async_context(
            self.wait_for_event_peer(
                public_key,
                [NodeState.CONNECTED],
                list(PathType),
                is_exit=True,
                timeout=timeout,
            )
        ) as event:
            await self.get_proxy().connect_to_exit_node(
                public_key=public_key, allowed_ips=None, endpoint=None
            )
            await event

    def get_router(self) -> Router:
        return self._router

    def get_runtime(self) -> Runtime:
        assert self._runtime
        return self._runtime

    def get_process(self) -> Process:
        assert self._process
        return self._process

    def get_proxy(self) -> LibtelioProxy:
        assert self._libtelio_proxy
        return self._libtelio_proxy

    def get_events(self) -> Events:
        assert self._events
        return self._events

    def get_stdout(self) -> str:
        assert self._process
        return self._process.get_stdout()

    def get_stderr(self) -> str:
        assert self._process
        return self._process.get_stderr()

    def get_features(self) -> Features:
        assert self._telio_features
        return self._telio_features

    def allow_errors(self, allowed_errors: List[str]) -> None:
        if self._allowed_errors is None:
            self._allowed_errors = []
        self._allowed_errors.extend(re.compile(e) for e in allowed_errors)

    async def stop_device(self) -> None:
        await self.get_proxy().stop()
        self._interface_configured = False

        # Check every .5s, up to maximum 10 seconds, that the started and stopped tasks are the same
        for i in range(20, -1, -1):
            started_tasks = self.get_runtime().get_started_tasks()
            stopped_tasks = self.get_runtime().get_stopped_tasks()
            diff = Counter(started_tasks) - Counter(stopped_tasks)
            if diff == Counter():
                break
            if i > 0:
                await asyncio.sleep(0.5)
            else:
                assert diff == Counter(), (
                    f"started tasks and stopped tasks differ! diff: {diff} | started"
                    f" tasks: {started_tasks} | stopped tasks: {stopped_tasks}"
                )

    def get_node_state(self, public_key: str) -> Optional[TelioNode]:
        return self.get_runtime().get_peer_info(public_key)

    def get_derp_state(self, server_ip: str) -> Optional[Server]:
        return self.get_runtime().get_derp_info(server_ip)

    async def _event_request_loop(self) -> None:
        while True:
            try:
                event = await self.get_proxy().next_event()
                while event:
                    if self._runtime:
                        log.info("[%s] -> %s @ %s", self._node.name, event[1], event[0])
                        self._runtime.handle_event(event[1], event[0])
                        event = await self.get_proxy().next_event()
                await asyncio.sleep(0.1)
            except:
                if self._quit:
                    return
                raise

    async def maybe_write_device_fingerprint_to_moose_db(self):
        if self._fingerprint is not None:
            await self.wait_for_log("[Moose] Init callback success")
            database, fingerprint = self._fingerprint
            max_retries = MOOSE_DB_TIMEOUT_MS / 1000
            max_timeout = MOOSE_DB_TIMEOUT_MS / 30

            while max_retries:
                try:
                    await self._connection.create_process(
                        [
                            "sqlite3",
                            database,
                            "--cmd",
                            f"PRAGMA busy_timeout = {max_timeout};",
                            (
                                "INSERT OR REPLACE INTO shared_context (key, val, is_essential) VALUES"
                                f" ('device.fp._string', '\"{fingerprint}\"', 1)"
                            ),
                        ],
                        quiet=True,
                    ).execute()
                    return
                except Exception as e:  # pylint: disable=broad-exception-caught
                    print(
                        f"maybe_write_device_fingerprint_to_moose_db error: {e}, retrying ..."
                    )
                    max_retries -= 1
                    await asyncio.sleep(0.1)
            if not max_retries:
                raise Exception(
                    "Retries exhausted, while trying to write fingerprint to db"
                )

    async def trigger_event_collection(self) -> None:
        await self.get_proxy().trigger_analytics_event()

    async def trigger_qos_collection(self) -> None:
        await self.get_proxy().trigger_qos_collection()

    def get_endpoint_address(self, public_key: str) -> str:
        node = self.get_node_state(public_key)
        if node is None:
            raise Exception(f"Node {public_key} doesn't exist")
        if node.endpoint is None:
            raise Exception(f"Node {public_key} endpoint doesn't exist")
        return node.endpoint.split(":")[0]

    def wait_for_output(self, what: str) -> asyncio.Event:
        event = asyncio.Event()
        self.get_runtime().get_output_notifier().notify_output(what, event)
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
        return await get_log_without_flush(self._connection)

    async def clear_system_log(self) -> None:
        """
        Clear the system log on the target machine
        Windows only for now
        """
        if self._connection.target_os == TargetOS.Windows:
            for log_name in ["Application", "System"]:
                await self._connection.create_process(
                    [
                        "powershell",
                        "-Command",
                        f"Clear-EventLog -LogName {log_name}",
                    ],
                    quiet=True,
                ).execute()

    async def flush_logs(self) -> None:
        await self.get_proxy().flush_logs()
