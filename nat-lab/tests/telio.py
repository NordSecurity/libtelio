# pylint: disable=too-many-lines

import asyncio
import json
import os
import platform
import random
import re
import shlex
import uniffi.telio_bindings as libtelio  # type: ignore
import uuid
from collections import Counter
from config import DERP_PRIMARY, DERP_SERVERS
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from dataclasses_json import DataClassJsonMixin, dataclass_json
from datetime import datetime
from enum import Enum
from mesh_api import Meshmap, Node, start_tcpdump, stop_tcpdump
from telio_features import TelioFeatures
from typing import AsyncIterator, List, Optional, Set
from uniffi.libtelio_proxy import LibtelioProxy, ProxyConnectionError
from utils import asyncio_util
from utils.connection import Connection, DockerConnection, TargetOS
from utils.connection_util import get_libtelio_binary_path, get_uniffi_path
from utils.output_notifier import OutputNotifier
from utils.process import Process, ProcessExecError
from utils.router import IPStack, Router, new_router
from utils.router.linux_router import LinuxRouter, FWMARK_VALUE as LINUX_FWMARK_VALUE
from utils.router.mac_router import MacRouter
from utils.router.windows_router import WindowsRouter
from utils.testing import test_name_safe_for_file_name


# Equivalent of `libtelio/telio-wg/src/uapi.rs`
class State(Enum):
    Disconnected = "disconnected"
    Connecting = "connecting"
    Connected = "connected"


class LinkState(Enum):
    Down = "down"
    Up = "up"


# Equivalent of `libtelio/crates/telio-model/src/features.rs:PathType`
class PathType(Enum):
    Relay = "relay"
    Direct = "direct"


@dataclass_json
@dataclass
class DerpServer(DataClassJsonMixin):
    region_code: str
    name: str
    hostname: str
    ipv4: str
    relay_port: int
    stun_port: int
    stun_plaintext_port: int
    public_key: str
    weight: int
    use_plain_text: bool
    conn_state: State
    # Only for compatibility with telio v3.6
    used: bool = False

    def __hash__(self):
        return hash((
            self.region_code,
            self.name,
            self.hostname,
            self.ipv4,
            self.relay_port,
            self.stun_port,
            self.stun_plaintext_port,
            self.public_key,
            self.weight,
            self.use_plain_text,
            self.conn_state,
        ))


# Equivalent of `libtelio/crates/telio-model/src/mesh.rs:Node`
@dataclass_json
@dataclass
class PeerInfo(DataClassJsonMixin):
    identifier: str = ""
    public_key: str = ""
    state: State = State.Disconnected
    link_state: Optional[LinkState] = None
    is_exit: bool = False
    is_vpn: bool = False
    ip_addresses: List[str] = field(default_factory=lambda: [])
    allowed_ips: List[str] = field(default_factory=lambda: [])
    nickname: Optional[str] = None
    endpoint: Optional[str] = None
    hostname: Optional[str] = None
    allow_incoming_connections: bool = False
    allow_peer_send_files: bool = False
    path: PathType = PathType.Relay

    def __hash__(self):
        return hash((
            self.identifier,
            self.public_key,
            self.state,
            self.link_state,
            self.is_exit,
            self.is_vpn,
            tuple(self.ip_addresses),
            tuple(self.allowed_ips),
            self.nickname,
            self.endpoint,
            self.hostname,
            self.allow_incoming_connections,
            self.allow_peer_send_files,
            self.path,
        ))

    def __eq__(self, other):
        if not isinstance(other, PeerInfo):
            return False
        return (
            self.identifier == other.identifier
            and self.public_key == other.public_key
            and self.state == other.state
            and (
                self.link_state is None
                or other.link_state is None
                or self.link_state == other.link_state
            )
            and self.is_exit == other.is_exit
            and self.is_vpn == other.is_vpn
            and self.ip_addresses == other.ip_addresses
            and self.allowed_ips == other.allowed_ips
            and (
                self.endpoint is None
                or other.endpoint is None
                or self.endpoint == other.endpoint
            )
            and (
                self.hostname is None
                or other.hostname is None
                or self.hostname == other.hostname
            )
            and (
                self.nickname is None
                or other.nickname is None
                or self.nickname == other.nickname
            )
            and self.allow_incoming_connections == other.allow_incoming_connections
            and self.allow_peer_send_files == other.allow_peer_send_files
            and self.path == other.path
        )


class ErrorLevel(Enum):
    Critical = "critical"
    Severe = "severe"
    Warning = "warning"
    Notice = "notice"


class ErrorCode(Enum):
    NoError = "noerror"
    Unknown = "unknown"


@dataclass_json
@dataclass
class ErrorEvent(DataClassJsonMixin):
    level: ErrorLevel = ErrorLevel.Critical
    code: ErrorCode = ErrorCode.NoError
    msg: str = ""


# Equivalent of `libtelio/telio-wg/src/adapter/mod.rs`
class AdapterType(Enum):
    Default = ""
    BoringTun = "boringtun"
    LinuxNativeWg = "linux-native"
    WireguardGo = "wireguard-go"
    WindowsNativeWg = "wireguard-nt"

    def convert_adapter_type(self, router: Router) -> libtelio.TelioAdapterType:
        if self == AdapterType.BoringTun:
            return libtelio.TelioAdapterType.BORING_TUN
        if self == AdapterType.LinuxNativeWg:
            return libtelio.TelioAdapterType.LINUX_NATIVE_TUN
        if self == AdapterType.WireguardGo:
            return libtelio.TelioAdapterType.WIREGUARD_GO_TUN
        if self == AdapterType.WindowsNativeWg:
            return libtelio.TelioAdapterType.WINDOWS_NATIVE_TUN
        if isinstance(router, WindowsRouter):
            return libtelio.TelioAdapterType.WIREGUARD_GO_TUN
        return libtelio.TelioAdapterType.BORING_TUN


class Runtime:
    _output_notifier: OutputNotifier
    _peer_state_events: List[PeerInfo]
    _derp_state_events: List[DerpServer]
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

    def handle_output_line(self, line) -> bool:
        return (
            self._handle_node_event(line)
            or self._output_notifier.handle_output(line)
            or self._handle_derp_event(line)
            or self._handle_task_information(line)
            or self._handle_error_event(line)
        )

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

    def get_output_notifier(self) -> OutputNotifier:
        return self._output_notifier

    async def notify_peer_state(
        self,
        public_key: str,
        states: List[State],
        paths: List[PathType],
        is_exit: bool = False,
        is_vpn: bool = False,
    ) -> None:
        while True:
            peer = self.get_peer_info(public_key)
            if (
                peer
                and peer.path in paths
                and peer.state in states
                and is_exit == peer.is_exit
                and is_vpn == peer.is_vpn
            ):
                return
            await asyncio.sleep(0.1)

    async def notify_peer_event(
        self,
        public_key: str,
        states: List[State],
        paths: List[PathType],
        is_exit: bool = False,
        is_vpn: bool = False,
    ) -> None:
        def _get_events() -> List[PeerInfo]:
            return [
                peer
                for peer in self._peer_state_events
                if peer
                and peer.public_key == public_key
                and peer.path in paths
                and peer.state in states
                and is_exit == peer.is_exit
                and is_vpn == peer.is_vpn
            ]

        old_events = _get_events()

        while True:
            new_events = _get_events()[len(old_events) :]
            if new_events:
                return
            await asyncio.sleep(0.1)

    def get_link_state_events(self, public_key: str) -> List[Optional[LinkState]]:
        return [
            peer.link_state
            for peer in self._peer_state_events
            if peer and peer.public_key == public_key
        ]

    def get_peer_info(self, public_key: str) -> Optional[PeerInfo]:
        events = [
            peer_event
            for peer_event in self._peer_state_events
            if peer_event.public_key == public_key
        ]
        if events:
            return events[-1]
        return None

    async def notify_derp_state(
        self,
        server_ip: str,
        states: List[State],
    ) -> None:
        while True:
            derp = self.get_derp_info(server_ip)
            if derp and derp.ipv4 == server_ip and derp.conn_state in states:
                return
            await asyncio.sleep(0.1)

    async def notify_derp_event(
        self,
        server_ip: str,
        states: List[State],
    ) -> None:
        def _get_events() -> List[DerpServer]:
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

    def get_derp_info(self, server_ip: str) -> Optional[DerpServer]:
        events = [event for event in self._derp_state_events if event.ipv4 == server_ip]
        if events:
            return events[-1]
        return None

    def set_peer(self, peer: PeerInfo) -> None:
        assert peer.public_key in self.allowed_pub_keys
        self._peer_state_events.append(peer)

    def _extract_event_tokens(self, line: str, event_type: str) -> Optional[List[str]]:
        if line.startswith(f'{{"type":"{event_type}","body":'):
            return line[:-1].split(f'{{"type":"{event_type}","body":')
        return None

    def _handle_node_event(self, line) -> bool:
        def _check_node_event(node_event: PeerInfo):
            assert node_event.is_exit or (
                "0.0.0.0/0" not in node_event.allowed_ips
                and "::/0" not in node_event.allowed_ips
            )

        tokens = self._extract_event_tokens(line, "node")
        if tokens is None:
            return False

        json_string = tokens[1].strip()
        result = re.search("{(.*)}", json_string)
        if result:
            node_state = PeerInfo.from_json(
                "{" + result.group(1).replace("\\", "") + "}"
            )
            assert isinstance(node_state, PeerInfo)
            _check_node_event(node_state)
            self.set_peer(node_state)
            return True
        return False

    def set_derp(self, derp: DerpServer) -> None:
        self._derp_state_events.append(derp)

    def _handle_derp_event(self, line) -> bool:
        tokens = self._extract_event_tokens(line, "relay")
        if tokens is None:
            return False

        json_string = tokens[1].strip()
        result = re.search("{(.*)}", json_string)
        if result:
            derp_server_json = DerpServer.from_json(
                # Added "used" variable for compatibility with telio 3.6
                "{"
                + result.group(1).replace("\\", "")
                + "}"
            )
            assert isinstance(derp_server_json, DerpServer)
            self.set_derp(derp_server_json)
            return True
        return False

    def get_started_tasks(self) -> List[str]:
        return self._started_tasks

    def get_stopped_tasks(self) -> List[str]:
        return self._stopped_tasks

    def _handle_error_event(self, line) -> bool:
        tokens = self._extract_event_tokens(line, "error")
        if tokens is None:
            return False

        json_string = tokens[1].strip()
        result = re.search("{(.*)}", json_string)
        if result:
            error_event = ErrorEvent.from_json(
                "{" + result.group(1).replace("\\", "") + "}"
            )
            assert isinstance(error_event, ErrorEvent)
            self._error_events.append(error_event)
            return True
        return False

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

    async def message_done(self, message_idx: int) -> None:
        event = asyncio.Event()
        self._runtime.get_output_notifier().notify_output(
            f"MESSAGE_DONE={message_idx}", event
        )
        await event.wait()

    async def wait_for_state_peer(
        self,
        public_key: str,
        state: List[State],
        paths: List[PathType],
        is_exit: bool = False,
        is_vpn: bool = False,
        timeout: Optional[float] = None,
    ) -> None:
        await asyncio.wait_for(
            self._runtime.notify_peer_state(public_key, state, paths, is_exit, is_vpn),
            timeout,
        )

    async def wait_for_event_peer(
        self,
        public_key: str,
        states: List[State],
        paths: List[PathType],
        is_exit: bool = False,
        is_vpn: bool = False,
        timeout: Optional[float] = None,
    ) -> None:
        await asyncio.wait_for(
            self._runtime.notify_peer_event(public_key, states, paths, is_exit, is_vpn),
            timeout,
        )

    def get_link_state_events(self, public_key: str) -> List[Optional[LinkState]]:
        return self._runtime.get_link_state_events(public_key)

    async def wait_for_state_derp(
        self, server_ip: str, states: List[State], timeout: Optional[float] = None
    ) -> None:
        await asyncio.wait_for(
            self._runtime.notify_derp_state(server_ip, states), timeout
        )

    async def wait_for_event_derp(
        self, server_ip: str, states: List[State], timeout: Optional[float] = None
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
        adapter_type: AdapterType = AdapterType.Default,
        telio_features: TelioFeatures = TelioFeatures(),
        force_ipv6_feature: bool = False,
    ) -> None:
        self._router: Optional[Router] = None
        self._events: Optional[Events] = None
        self._runtime: Optional[Runtime] = None
        self._process: Optional[Process] = None
        self._interface_configured = False
        self._message_idx = 0
        self._node = node
        self._connection = connection
        self._adapter_type = adapter_type
        self._telio_features = telio_features
        self._quit = False
        self._start_time = datetime.now()
        self._libtelio_proxy: Optional[LibtelioProxy] = None
        # Automatically enables IPv6 feature when the IPv6 stack is enabled
        if (
            self._node.ip_stack in (IPStack.IPv4v6, IPStack.IPv6)
            and not force_ipv6_feature
        ):
            self._telio_features.ipv6 = True

    @asynccontextmanager
    async def run(
        self, meshmap: Optional[Meshmap] = None, telio_v3: bool = False
    ) -> AsyncIterator["Client"]:
        if isinstance(self._connection, DockerConnection):
            start_tcpdump(self._connection.container_name())
            await self.clear_core_dumps()

        async def on_stdout(stdout: str) -> None:
            supress_print_list = [
                "MESSAGE_DONE=",
                "- no login.",
                "- telio running.",
                "- telio nodes",
                "task stopped - ",
                "task started - ",
            ]
            for line in stdout.splitlines():
                if not any(string in line for string in supress_print_list):
                    print(f"[{self._node.name}]: stdout: {line}")
                if self._runtime:
                    self._runtime.handle_output_line(line)

        async def on_stderr(stdout: str) -> None:
            for line in stdout.splitlines():
                print(f"[{self._node.name}]: stderr: {line}")
                if self._runtime:
                    self._runtime.handle_output_line(line)

        self._runtime = Runtime()
        self._events = Events(self._runtime)
        self._router = new_router(self._connection, self._node.ip_stack)

        object_name = str(uuid.uuid4()).replace("-", "")
        (host_ip, container_ip) = await self._connection.get_ip_address()

        host_os = platform.system()
        if host_os == "Linux":
            host_ip = container_ip
            port = str(random.randrange(10000, 65000))
            (host_port, container_port) = (port, port)
        elif host_os in ("Windows", "Darwin"):
            (host_port, container_port) = await self._connection.mapped_ports()
        else:
            raise RuntimeError(f"Unsupported host OS: {host_os}")

        object_uri = f"PYRO:{object_name}@{host_ip}:{host_port}"

        if isinstance(self.get_router(), WindowsRouter):
            python_cmd = "python"
        else:
            python_cmd = "python3"
        uniffi_path = get_uniffi_path(self._connection)

        if isinstance(self.get_router(), MacRouter):
            uniprocess = self._connection.create_process(["/bin/sh"])
        else:
            uniprocess = self._connection.create_process([
                python_cmd,
                uniffi_path,
                object_name,
                container_ip,
                container_port,
            ])

        tcli_path = get_libtelio_binary_path("tcli", self._connection)
        if telio_v3:
            self._process = self._connection.create_process([
                "/opt/bin/tcli-3.6",
                "--less-spam",
                '-f { "paths": { "priority": ["relay", "udp-hole-punch"]} }',
            ])
        else:
            self._process = self._connection.create_process([
                tcli_path,
                "--less-spam",
                f"-f {self._telio_features.to_json()}",
            ])

        await self.clear_system_log()

        async with self._process.run(
            stdout_callback=on_stdout, stderr_callback=on_stderr
        ):
            async with uniprocess.run(
                stdout_callback=on_stdout, stderr_callback=on_stderr
            ):
                try:
                    await self._process.wait_stdin_ready()
                    await uniprocess.wait_stdin_ready()

                    if isinstance(self.get_router(), MacRouter):
                        await uniprocess.escape_and_write_stdin(
                            ["source", "/etc/profile"]
                        )
                        await uniprocess.escape_and_write_stdin([
                            python_cmd,
                            uniffi_path,
                            object_name,
                            container_ip,
                            container_port,
                        ])

                    try:
                        self._libtelio_proxy = LibtelioProxy(
                            object_uri, self._telio_features.to_json()
                        )
                    except ProxyConnectionError as err:
                        print(str(err))
                        raise err

                    self.get_proxy().start_named(
                        private_key=self._node.private_key,
                        adapter=self._adapter_type.convert_adapter_type(
                            self.get_router()
                        ),
                        name=self.get_router().get_interface_name(),
                    )
                    if isinstance(self.get_router(), LinuxRouter):
                        self.get_proxy().set_fwmark(int(LINUX_FWMARK_VALUE))

                    async with asyncio_util.run_async_context(
                        self._event_request_loop()
                    ):
                        if meshmap:
                            await self.set_meshmap(meshmap)
                        yield self
                finally:
                    print(datetime.now(), "Test cleanup stage 1. Saving logs")
                    await self.save_logs()

                    print(
                        datetime.now(),
                        "Test cleanup stage 2. Stopping tcpdump and collecting core dumps",
                    )
                    if isinstance(self._connection, DockerConnection):
                        stop_tcpdump([self._connection.container_name()])
                        await self.collect_core_dumps()

                    print(
                        datetime.now(),
                        "Test cleanup stage 3. Saving MacOS network info",
                    )
                    await self.save_mac_network_info()

                    print(datetime.now(), "Test cleanup stage 4. Stopping device")
                    if self._process.is_executing():
                        await self.stop_device()
                        self._quit = True

                    print(datetime.now(), "Test cleanup stage 5. Shutting down")
                    self.get_proxy().shutdown(self._connection.target_name())

                    print(datetime.now(), "Test cleanup stage 6. Clearing up routes")
                    if self._router:
                        await self._router.delete_vpn_route()
                        await self._router.delete_exit_node_route()
                        await self._router.delete_interface()

                    print(datetime.now(), "Test cleanup complete")

    async def simple_start(self):
        self.get_proxy().start_named(
            private_key=self._node.private_key,
            adapter=self._adapter_type.convert_adapter_type(self.get_router()),
            name=self.get_router().get_interface_name(),
        )
        if isinstance(self.get_router(), LinuxRouter):
            self.get_proxy().set_fwmark(int(LINUX_FWMARK_VALUE))

    async def wait_for_state_peer(
        self,
        public_key,
        states: List[State],
        paths: Optional[List[PathType]] = None,
        is_exit: bool = False,
        is_vpn: bool = False,
        timeout: Optional[float] = None,
    ) -> None:
        await self.get_events().wait_for_state_peer(
            public_key,
            states,
            paths if paths else [PathType.Relay],
            is_exit,
            is_vpn,
            timeout,
        )

    async def wait_for_event_peer(
        self,
        public_key: str,
        states: List[State],
        paths: Optional[List[PathType]] = None,
        is_exit: bool = False,
        is_vpn: bool = False,
        timeout: Optional[float] = None,
    ) -> None:
        await self.get_events().wait_for_event_peer(
            public_key,
            states,
            paths if paths else [PathType.Relay],
            is_exit,
            is_vpn,
            timeout,
        )

    def get_link_state_events(self, public_key: str) -> List[Optional[LinkState]]:
        return self.get_events().get_link_state_events(public_key)

    async def wait_for_state_derp(
        self, derp_ip, states: List[State], timeout: Optional[float] = None
    ) -> None:
        await self.get_events().wait_for_state_derp(derp_ip, states, timeout)

    async def wait_for_state_on_any_derp(
        self, states: List[State], timeout: Optional[float] = None
    ) -> None:
        async with asyncio_util.run_async_contexts([
            self.get_events().wait_for_state_derp(str(derp["ipv4"]), states, timeout)
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
                str(derp["ipv4"]), [State.Disconnected, State.Connecting], timeout
            )
            for derp in DERP_SERVERS
        ]) as futures:
            try:
                while not all(fut.done() for fut in futures):
                    await asyncio.sleep(0.1)
            except asyncio.CancelledError:
                pass

    async def wait_for_event_derp(
        self, derp_ip, states: List[State], timeout: Optional[float] = None
    ) -> None:
        await self.get_events().wait_for_event_derp(derp_ip, states, timeout)

    async def wait_for_event_on_any_derp(
        self, states: List[State], timeout: Optional[float] = None
    ) -> None:
        async with asyncio_util.run_async_contexts([
            self.get_events().wait_for_event_derp(str(derp["ipv4"]), states, timeout)
            for derp in DERP_SERVERS
        ]) as futures:
            try:
                while not any(fut.done() for fut in futures):
                    await asyncio.sleep(0.1)
            except asyncio.CancelledError:
                pass

    async def wait_for_event_error(self, err: ErrorEvent):
        await self.get_events().wait_for_event_error(err)

    async def set_meshmap(self, meshmap: Meshmap) -> None:
        made_changes = await self._configure_interface()

        # Linux native WG takes ~1.5s to setup listen port for WG interface. Since
        # listen port is required for mesh connection, there is no other way to
        # bypass this waiting period. Another option would be to retry `mesh config`
        # multiple times until the command succeeds.
        if made_changes and self._adapter_type == AdapterType.LinuxNativeWg:
            await asyncio.sleep(2)

        if "peers" in meshmap:
            peers = meshmap["peers"]
            for peer in peers:
                self.get_runtime().allowed_pub_keys.add(peer["public_key"])

        self.get_proxy().set_meshnet(json.dumps(meshmap))

    async def set_mesh_off(self):
        self.get_proxy().set_meshnet_off()

    async def receive_ping(self):
        await self._write_command(["mesh", "ping"])

    async def connect_to_vpn(
        self,
        ip: str,
        port: int,
        public_key: str,
        timeout: Optional[float] = None,
        pq: bool = False,
    ) -> None:
        await self._configure_interface()
        await self.get_router().create_vpn_route()
        async with asyncio_util.run_async_context(
            self.wait_for_event_peer(
                public_key,
                [State.Connected],
                list(PathType),
                is_exit=True,
                is_vpn=True,
                timeout=timeout,
            )
        ) as event:
            self.get_runtime().allowed_pub_keys.add(public_key)

            if pq:
                self.get_proxy().connect_to_exit_node_pq(
                    public_key=public_key,
                    allowed_ips=None,
                    endpoint=f"{ip}:{port}",
                )
            else:
                self.get_proxy().connect_to_exit_node(
                    public_key=public_key,
                    allowed_ips=None,
                    endpoint=f"{ip}:{port}",
                )
            await event

    async def set_secret_key(self, secret_key: str):
        self.get_proxy().set_secret_key(secret_key)

    async def disconnect_from_vpn(
        self,
        public_key: str,
        timeout: Optional[float] = None,
    ) -> None:
        async with asyncio_util.run_async_context(
            self.wait_for_event_peer(
                public_key,
                [State.Disconnected],
                list(PathType),
                is_exit=True,
                is_vpn=True,
                timeout=timeout,
            )
        ) as event:
            self.get_proxy().disconnect_from_exit_nodes()
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
                public_key, [State.Connected], list(PathType), timeout=timeout
            )
        ) as event:
            self.get_proxy().disconnect_from_exit_nodes()
            await asyncio.gather(
                event,
                self.get_router().delete_vpn_route(),
            )

    async def enable_magic_dns(self, forward_servers: List[str]) -> None:
        self.get_proxy().enable_magic_dns(forward_servers)

    async def disable_magic_dns(self) -> None:
        self.get_proxy().disable_magic_dns()

    async def notify_network_change(self) -> None:
        self.get_proxy().notify_network_change()

    async def _configure_interface(self) -> bool:
        if not self._interface_configured:
            await self.get_router().setup_interface(self._node.ip_addresses)

            await self.get_router().create_meshnet_route()
            self._interface_configured = True
            return True

        return False

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
                [State.Connected],
                list(PathType),
                is_exit=True,
                timeout=timeout,
            )
        ) as event:
            self.get_proxy().connect_to_exit_node(
                public_key=public_key, allowed_ips=None, endpoint=None
            )
            await event

    def get_router(self) -> Router:
        assert self._router
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

    def get_features(self) -> TelioFeatures:
        assert self._telio_features
        return self._telio_features

    async def stop_device(self) -> None:
        self.get_proxy().stop()
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
                assert (
                    diff == Counter()
                ), f"started tasks and stopped tasks differ! diff: {diff} | started tasks: {started_tasks} | stopped tasks: {stopped_tasks}"

    def get_node_state(self, public_key: str) -> Optional[PeerInfo]:
        return self.get_runtime().get_peer_info(public_key)

    def get_derp_state(self, server_ip: str) -> Optional[DerpServer]:
        return self.get_runtime().get_derp_info(server_ip)

    async def _event_request_loop(self) -> None:
        while True:
            try:
                event = self.get_proxy().next_event()
                while event:
                    if self._runtime:
                        print(
                            f"[{self._node.name}]: event [{datetime.now()}]:"
                            f" {event}"
                        )
                        self._runtime.handle_output_line(event)
                        event = self.get_proxy().next_event()
                await asyncio.sleep(1)
            except:
                if self._quit:
                    return
                raise

    async def create_fake_derprelay_to_derp01(self, sk: str, allowed_pk: str) -> None:
        derp01_server = (
            '{"host":"'
            + str(DERP_PRIMARY["hostname"])
            + '","ipv4":"'
            + str(DERP_PRIMARY["ipv4"])
            + '","port":'
            + str(DERP_PRIMARY["relay_port"])
            + ',"pk":"'
            + str(DERP_PRIMARY["public_key"])
            + '"}'
        )

        await self._write_command(["derp", "on", sk, derp01_server, allowed_pk])

    async def disconnect_fake_derprelay(self) -> None:
        await self._write_command(["derp", "off"])

    async def recv_message_from_fake_derp_relay(self) -> None:
        await self._write_command(["derp", "recv"])

    async def fake_derp_events(self) -> None:
        await self._write_command(["derp", "events"])

    async def send_message_from_fake_derp_relay(self, pk: str, data: List[str]) -> None:
        await self._write_command(["derp", "send", pk] + data)

    async def trigger_event_collection(self) -> None:
        self.get_proxy().trigger_analytics_event()

    async def trigger_qos_collection(self) -> None:
        self.get_proxy().trigger_qos_collection()

    async def _write_command(self, command: List[str]) -> None:
        idx = self._message_idx
        cmd = (
            f"MESSAGE_ID={str(idx)} "
            + " ".join([shlex.quote(arg) for arg in command])
            + "\n"
        )
        await self.get_process().write_stdin(cmd)
        self._message_idx += 1
        await self.get_events().message_done(idx)

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

    async def wait_for_log(self, what: str, case_insensitive: bool = True) -> None:
        if case_insensitive:
            what = what.lower()
        while True:
            if what in (await self.get_log()).lower():
                break
            await asyncio.sleep(1)

    async def get_log(self) -> str:
        process = (
            self._connection.create_process(["type", "tcli.log"])
            if self._connection.target_os == TargetOS.Windows
            else self._connection.create_process(["cat", "./tcli.log"])
        )
        await process.execute()
        return process.get_stdout()

    async def get_system_log(self) -> Optional[str]:
        """
        Get the system log on the target machine
        Windows only for now
        """
        if self._connection.target_os == TargetOS.Windows:
            logs = ""
            for log_name in ["Application", "System"]:
                try:
                    log_output = await self._connection.create_process([
                        "powershell",
                        "-Command",
                        f"Get-EventLog -LogName {log_name} -Newest 100 | format-table -wrap",
                    ]).execute()
                    logs += log_output.get_stdout()
                except ProcessExecError:
                    # ignore exec error, since it happens if no events were found
                    pass
            return logs
        return None

    async def clear_system_log(self) -> None:
        """
        Clear the system log on the target machine
        Windows only for now
        """
        if self._connection.target_os == TargetOS.Windows:
            for log_name in ["Application", "System"]:
                await self._connection.create_process([
                    "powershell",
                    "-Command",
                    f"Clear-EventLog -LogName {log_name}",
                ]).execute()

    async def get_log_lines(self, regex: Optional[str] = None) -> List[str]:
        """
        Get the tcli log as a list of strings

        If regex is provided, only matching lines are returned (and only subset of lines that match the capture group).
        """
        log = await self.get_log()
        lines = log.split("\n")
        if regex:
            ret, compiled_regex = [], re.compile(regex)
            for line in lines:
                m = compiled_regex.match(line)
                if m:
                    ret.append(m.group(1))
            return ret
        return lines

    async def get_network_info(self) -> str:
        if self._connection.target_os == TargetOS.Mac:
            interface_info = self._connection.create_process(["ifconfig", "-a"])
            await interface_info.execute()
            routing_table_info = self._connection.create_process(["netstat", "-rn"])
            await routing_table_info.execute()
            # syslog does not provide a way to filter events by timestamp, so only using the last 20 lines.
            syslog_info = self._connection.create_process(["syslog"])
            await syslog_info.execute()
            start_time_str = self._start_time.strftime("%Y-%m-%d %H:%M:%S")
            log_info = self._connection.create_process(
                ["log", "show", "--start", start_time_str]
            )
            await log_info.execute()
            return (
                start_time_str
                + "\n"
                + "\n"
                + routing_table_info.get_stdout()
                + "\n"
                + interface_info.get_stdout()
                + "\n"
                + "\n".join(syslog_info.get_stdout().splitlines()[-20:])
                + "\n"
                + "\n"
                + log_info.get_stdout()
                + "\n"
                + "\n"
            )
        return ""

    async def save_logs(self) -> None:
        if os.environ.get("NATLAB_SAVE_LOGS") is None:
            return

        log_dir = "logs"
        os.makedirs(log_dir, exist_ok=True)

        log_content = await self.get_log()

        system_log_content = await self.get_system_log()

        if self._connection.target_os == TargetOS.Linux:
            process = self._connection.create_process(["cat", "/etc/hostname"])
            await process.execute()
            container_id = process.get_stdout().strip()
        else:
            container_id = str(self._connection.target_os)

        test_name = test_name_safe_for_file_name()

        filename = str(test_name) + "_" + container_id + ".log"
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
            if system_log_content:
                f.write("\n\n\n\n--- SYSTEM LOG ---\n\n")
                f.write(system_log_content)

    async def save_mac_network_info(self) -> None:
        if os.environ.get("NATLAB_SAVE_LOGS") is None:
            return

        if self._connection.target_os != TargetOS.Mac:
            return

        log_dir = "logs"
        os.makedirs(log_dir, exist_ok=True)

        network_info_info = await self.get_network_info()

        container_id = str(self._connection.target_os)

        test_name = test_name_safe_for_file_name()

        filename = str(test_name) + "_" + container_id + "_network_info"
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
            f.write(network_info_info)

    async def probe_pmtu(self, host: str, expected: int):
        ev = self.wait_for_output(f"PMTU -> {host}: {expected}")
        await self._write_command(["pmtu", host])
        await ev.wait()

    # This is where natlab expects coredumps to be placed
    # For CI and our internal linux VM, this path is set in our provisioning scripts
    # If you're running locally without the aforementioned linux VM, you are expected to configure this yourself
    # However, this only needs to be set iff you're:
    #  - running a test targeting a docker image
    #  - have set the NATLAB_SAVE_LOGS environment variable
    #  - want to have natlab automatically collect core dumps for you
    def get_coredump_folder(self) -> tuple[str, str]:
        return "/var/crash", "core-"

    def should_skip_core_dump_collection(self) -> bool:
        return (
            os.environ.get("NATLAB_SAVE_LOGS") is None
            or self._connection.target_os != TargetOS.Linux
        )

    async def clear_core_dumps(self):
        if self.should_skip_core_dump_collection():
            return

        coredump_folder, _ = self.get_coredump_folder()

        # clear the existing system core dumps
        await self._connection.create_process(["rm", "-rf", coredump_folder]).execute()
        # make sure we have the path where the new cores will be dumped
        await self._connection.create_process(
            ["mkdir", "-p", coredump_folder]
        ).execute()

    async def collect_core_dumps(self):
        if self.should_skip_core_dump_collection():
            return

        coredump_folder, file_prefix = self.get_coredump_folder()

        # find all core dump files
        process = await self._connection.create_process(
            ["find", coredump_folder, "-maxdepth", "1", "-name", f"{file_prefix}*"]
        ).execute()
        dump_files = process.get_stdout().strip().split()

        coredump_dir = "coredumps"
        os.makedirs(coredump_dir, exist_ok=True)

        should_copy_coredumps = len(dump_files) > 0

        # if we collected some core dumps, copy them
        if isinstance(self._connection, DockerConnection) and should_copy_coredumps:
            container_name = self._connection.container_name()
            test_name = test_name_safe_for_file_name()
            for i, file_path in enumerate(dump_files):
                file_name = file_path.rsplit("/", 1)[-1]
                core_dump_destination = (
                    f"{coredump_dir}/{test_name}_{file_name}_{i}.core"
                )
                cmd = f"docker container cp {container_name}:{file_path} {core_dump_destination}"
                os.system(cmd)


def generate_secret_key() -> str:
    return libtelio.generate_secret_key()


def generate_public_key(private_key: str) -> str:
    return libtelio.generate_public_key(private_key)
