# pylint: disable=too-many-lines
import asyncio
import glob
import os
import platform
import re
import socket
import uuid
import warnings
from collections import Counter
from config import DERP_SERVERS
from contextlib import AsyncExitStack, asynccontextmanager
from datetime import datetime
from mesh_api import Node
from typing import AsyncIterator, List, Optional, Set
from uniffi.libtelio_proxy import LibtelioProxy, ProxyConnectionError
from utils import asyncio_util
from utils.bindings import (
    default_features,
    Features,
    NatType,
    Config,
    TelioNode,
    Server,
    ErrorEvent,
    Event,
    PathType,
    NodeState,
    RelayState,
    LinkState,
    TelioAdapterType,
)
from utils.command_grepper import CommandGrepper
from utils.connection import Connection, TargetOS
from utils.connection.docker_connection import DockerConnection, container_id
from utils.connection_util import get_uniffi_path
from utils.moose import MOOSE_LOGS_DIR
from utils.output_notifier import OutputNotifier
from utils.process import Process, ProcessExecError
from utils.python import get_python_binary
from utils.router import IPStack, Router, new_router
from utils.router.linux_router import LinuxRouter, FWMARK_VALUE as LINUX_FWMARK_VALUE
from utils.router.windows_router import WindowsRouter
from utils.tcpdump import make_tcpdump
from utils.testing import (
    get_current_test_log_path,
    get_current_test_case_and_parameters,
)


class Runtime:
    _output_notifier: OutputNotifier
    _peer_state_events: List[TelioNode]
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

    def handle_event(self, event: Event):
        if isinstance(event, Event.NODE):
            self._handle_node_event(event.body)
        elif isinstance(event, Event.RELAY):
            self._handle_derp_event(event.body)
        elif isinstance(event, Event.ERROR):
            self._handle_error_event(event.body)
        else:
            raise TypeError(f"Got invalid event type: {event}")

    def _handle_node_event(self, node_event: TelioNode):
        assert node_event.is_exit or (
            "0.0.0.0/0" not in node_event.allowed_ips
            and "::/0" not in node_event.allowed_ips
        )
        self.set_peer(node_event)

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
    ) -> None:
        def _get_events() -> List[TelioNode]:
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

    def get_link_state_events(self, public_key: str) -> List[LinkState]:
        return [
            peer.link_state
            for peer in self._peer_state_events
            if peer and peer.public_key == public_key and peer.link_state is not None
        ]

    def get_peer_info(self, public_key: str) -> Optional[TelioNode]:
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

    def set_peer(self, peer: TelioNode) -> None:
        assert peer.public_key in self.allowed_pub_keys
        self._peer_state_events.append(peer)

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
    ) -> None:
        await asyncio.wait_for(
            self._runtime.notify_peer_state(
                public_key, state, paths, is_exit, is_vpn, link_state
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
    ) -> None:
        await asyncio.wait_for(
            self._runtime.notify_peer_event(public_key, states, paths, is_exit, is_vpn),
            timeout,
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
        #   Windows -> WireguardGo
        #   All other platforms -> NepTUN
        if adapter_type is not None:
            self._adapter_type = adapter_type
        elif isinstance(self.get_router(), WindowsRouter):
            self._adapter_type = TelioAdapterType.WIREGUARD_GO_TUN
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

    @asynccontextmanager
    async def run(
        self, meshnet_config: Optional[Config] = None
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
                    print(f"[{self._node.name}]: stdout: {line}")
                if self._runtime:
                    await self._runtime.handle_output_line(line)

        async def on_stderr(stderr: str) -> None:
            for line in stderr.splitlines():
                print(f"[{self._node.name}]: stderr: {line}")
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

        self._process = self._connection.create_process([
            python_cmd,
            uniffi_path,
            object_name,
            container_ip,
            container_port,
        ])

        async with AsyncExitStack() as exit_stack:
            await exit_stack.enter_async_context(make_tcpdump([self._connection]))
            if isinstance(self._connection, DockerConnection):
                await self.clear_core_dumps()

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
                    while len(self._proxy_port) == 0:
                        await asyncio.sleep(0.25)
                    object_uri = f"PYRO:{object_name}@{host_ip}:{self._proxy_port}"
                else:
                    object_uri = f"PYRO:{object_name}@localhost:{host_port}"

                self._libtelio_proxy = LibtelioProxy(object_uri, self._telio_features)
                try:
                    await self.get_proxy().create()
                except ProxyConnectionError as err:
                    print(str(err))
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
                    yield self
            finally:
                print(
                    datetime.now(),
                    "Test cleanup: Stopping tcpdump and collecting core dumps",
                )
                if isinstance(self._connection, DockerConnection):
                    await self.collect_core_dumps()

                print(
                    datetime.now(),
                    "Test cleanup: Saving MacOS network info",
                )
                await self.save_mac_network_info()

                print(datetime.now(), "Test cleanup: Stopping device")
                if self._process.is_executing():
                    if self._libtelio_proxy:
                        await self.stop_device()
                    else:
                        print(
                            datetime.now(),
                            "[Debug] We don't have LibtelioProxy instance, Stop() not called.",
                        )
                    self._quit = True

                print(datetime.now(), "Test cleanup: Shutting down")
                if self._libtelio_proxy:
                    # flush_logs() is allowed to fail here:
                    try:
                        await self.get_proxy().flush_logs()
                    # Since this is clean up code, catching general exceptions is fine:
                    except Exception as e:  # pylint: disable=broad-exception-caught
                        print(
                            datetime.now(),
                            f"Test cleanup: Exception while flushing logs: {e}",
                        )

                    await self.get_proxy().shutdown(self._connection.tag.name)
                else:
                    print(
                        datetime.now(),
                        "[Debug] We don't have LibtelioProxy instance, Shutdown() not called.",
                    )

                print(datetime.now(), "Test cleanup: Clearing up routes")
                await self._router.delete_vpn_route()
                await self._router.delete_exit_node_route()
                await self._router.delete_interface()

                print(datetime.now(), "Test cleanup: Saving moose dbs")
                await self.save_moose_db()

                print(datetime.now(), "Test cleanup: Checking logs")
                await self._check_logs_for_errors()

                print(datetime.now(), "Test cleanup: Saving logs")
                await self._save_logs()

                print(datetime.now(), "Test cleanup complete")

    async def simple_start(self):
        await self.get_proxy().start_named(
            private_key=self._node.private_key,
            adapter=self._adapter_type,
            name=self.get_router().get_interface_name(),
        )
        if isinstance(self.get_router(), LinuxRouter):
            await self.get_proxy().set_fwmark(int(LINUX_FWMARK_VALUE))

    async def create_tun(self, tun_name: str) -> int:
        return await self.get_proxy().create_tun(tun_name)

    async def start_with_tun(self, tun: int, tun_name):
        await self.get_proxy().start_with_tun(
            private_key=self._node.private_key,
            adapter=self._adapter_type,
            tun=tun,
        )
        if isinstance(self.get_router(), LinuxRouter):
            self.get_router().set_interface_name(tun_name)
            await self.get_proxy().set_fwmark(int(LINUX_FWMARK_VALUE))

    async def wait_for_state_peer(
        self,
        public_key,
        states: List[NodeState],
        paths: Optional[List[PathType]] = None,
        is_exit: bool = False,
        is_vpn: bool = False,
        timeout: Optional[float] = None,
        link_state: Optional[LinkState] = None,
    ) -> None:
        await self.get_events().wait_for_state_peer(
            public_key,
            states,
            paths if paths else [PathType.RELAY],
            is_exit,
            is_vpn,
            timeout,
            link_state,
        )

    async def wait_for_link_state(
        self,
        public_key: str,
        state: LinkState,
        timeout: Optional[float] = None,
    ) -> None:
        """Wait until a link_state event matching the `state` for `public_key` is available."""
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
    ) -> None:
        event_info = f"peer({public_key}) with states({states}), paths({paths}), is_exit={is_exit}, is_vpn={is_vpn}"

        print(datetime.now(), f"[{self._node.name}]: wait for event {event_info}")
        await self.get_events().wait_for_event_peer(
            public_key,
            states,
            paths if paths else [PathType.RELAY],
            is_exit,
            is_vpn,
            timeout,
        )
        print(datetime.now(), f"[{self._node.name}]: got event {event_info}")

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
        await self.get_events().wait_for_event_derp(derp_ip, states, timeout)

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

    async def get_nat(self, ip: str, port: int) -> NatType:
        return await self.get_proxy().get_nat(ip, port)

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
                [NodeState.CONNECTED],
                list(PathType),
                is_exit=True,
                is_vpn=True,
                timeout=timeout,
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

    async def restart_interface(self):
        if self._interface_configured:
            await self.get_router().deconfigure_interface(self._node.ip_addresses)
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
                        print(f"[{self._node.name}]: event [{datetime.now()}]: {event}")
                        self._runtime.handle_event(event)
                        event = await self.get_proxy().next_event()
                await asyncio.sleep(1)
            except:
                if self._quit:
                    return
                raise

    async def maybe_write_device_fingerprint_to_moose_db(self):
        if self._fingerprint is not None:
            await self.wait_for_log("[Moose] Init callback success")
            database, fingerprint = self._fingerprint
            await self._connection.create_process([
                "sqlite3",
                database,
                "--cmd",
                "PRAGMA busy_timeout = 30000;",
                (
                    "INSERT OR REPLACE INTO shared_context (key, val, is_essential) VALUES"
                    f" ('device.fp._string', '\"{fingerprint}\"', 1)"
                ),
            ]).execute()

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
        self, what: str, case_insensitive: bool = True, count=1
    ) -> None:
        if case_insensitive:
            what = what.lower()
        while True:
            log = await self.get_log()
            if case_insensitive:
                log = log.lower()
            if log.count(what) >= count:
                break
            await asyncio.sleep(1)

    async def get_log(self) -> str:
        await self.flush_logs()
        return await self._get_log_without_flush()

    async def _get_log_without_flush(self) -> str:
        return await get_log_without_flush(self._connection)

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
                        (
                            f"Get-EventLog -LogName {log_name} -Newest 100 |"
                            " format-table -wrap"
                        ),
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

    async def _check_logs_for_errors(self) -> None:
        """
        Check logs for error and raise error/warning if unexpected errors
        has been found

        In order to check all of the logs this function must be called
        after process running libtelio has already exited. Or in worst case
        at least after logs has been flushed.
        """

        log_content = await self._get_log_without_flush()
        for line in log_content.splitlines():
            if "TelioLogLevel.ERROR" in line:
                if not self._allowed_errors or not any(
                    allowed.search(line) for allowed in self._allowed_errors
                ):
                    # TODO: convert back to `raise Exception()` once we are ready to investigate
                    warnings.warn(
                        f"Unexpected error found in {self._node.name} log: {line}"
                    )

    async def _save_logs(self) -> None:
        """
        Save the logs from libtelio.
        In order to collect all of the logs this function must be called
        after process running libtelio has already exited. Or in worst case
        at least after logs has been flushed.
        """

        if os.environ.get("NATLAB_SAVE_LOGS") is None:
            return
        base_dir = "logs"
        log_dir = get_current_test_log_path(base_dir)
        os.makedirs(log_dir, exist_ok=True)

        try:
            log_content = await self._get_log_without_flush()
        except ProcessExecError as err:
            err.print()
            return

        system_log_content = await self.get_system_log()
        conn_name = self._connection.tag.name.lower()
        filename = conn_name + ".log"
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

        # change the if to -> `true`
        if os.environ.get("GITHUB_SCHEDULE") == "true":
            processed_log = ""
            pattern = re.compile(r"^(\S+\s\S+)\s(TelioLogLevel\.\S+)\s(\S+Z)\s(.*)")
            (_, test_name) = os.path.split(log_dir)
            pipeline_id = os.environ.get("CI_PIPELINE_ID")
            job_id = os.environ.get("CI_JOB_ID")
            for log_line in log_content.splitlines():
                match = pattern.match(log_line)
                if match:
                    output = f"{pipeline_id} {job_id} {test_name} {conn_name} {match.group(3)} {match.group(2)} {match.group(4)}"
                    processed_log += output + "\n"
                else:
                    # Remove the carriage return
                    processed_log = processed_log[:-1]
                    processed_log += log_line + "\n"

            try:
                opensearch_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                for log_line in processed_log.splitlines():
                    # Send to vagrant_under_docker image
                    opensearch_socket.sendto(log_line.encode(), ("10.55.0.1", 12345))
                opensearch_socket.close()
            except (socket.gaierror, socket.error, UnicodeEncodeError) as e:
                print(f"Failed to send log line: {e}")

        moose_traces = await find_files(
            self._connection, MOOSE_LOGS_DIR, "moose_trace.log*"
        )
        for trace_path in moose_traces:
            copy_file(self._connection, trace_path, log_dir)
            file_name = os.path.basename(trace_path)
            os.rename(
                os.path.join(log_dir, file_name),
                os.path.join(
                    log_dir, f"{self._connection.tag.name.lower()}-{file_name}"
                ),
            )

    async def save_moose_db(self) -> None:
        """
        Check if any the moose db files exists ("*-events.db"),
        rename them to "str(test_name) + "_" + original_filename, and save them to "./logs",
        delete the original file.
        """
        if os.environ.get("NATLAB_SAVE_LOGS") is None:
            return

        log_dir = get_current_test_log_path()
        os.makedirs(log_dir, exist_ok=True)

        moose_db_files = glob.glob("*-events.db", recursive=False)

        for original_filename in moose_db_files:
            new_filepath = os.path.join(log_dir, original_filename)
            os.rename(original_filename, new_filepath)

    async def save_mac_network_info(self) -> None:
        if os.environ.get("NATLAB_SAVE_LOGS") is None:
            return

        if self._connection.target_os != TargetOS.Mac:
            return

        log_dir = get_current_test_log_path()
        os.makedirs(log_dir, exist_ok=True)

        network_info_info = await self.get_network_info()

        filename = self._connection.tag.name.lower() + "_network_info.log"
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

    async def probe_pmtu(self, host: str) -> int:
        return await self.get_proxy().probe_pmtu(host)

    async def flush_logs(self) -> None:
        await self.get_proxy().flush_logs()

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

        dump_files = await find_files(
            self._connection, coredump_folder, f"{file_prefix}*"
        )

        coredump_dir = "coredumps"
        os.makedirs(coredump_dir, exist_ok=True)

        should_copy_coredumps = len(dump_files) > 0

        # if we collected some core dumps, copy them
        if isinstance(self._connection, DockerConnection) and should_copy_coredumps:
            container_name = container_id(self._connection.tag)
            test_name = get_current_test_case_and_parameters()[0] or ""
            for i, file_path in enumerate(dump_files):
                file_name = file_path.rsplit("/", 1)[-1]
                core_dump_destination = (
                    f"{coredump_dir}/{test_name}_{file_name}_{i}.core"
                )
                cmd = (
                    "docker container cp"
                    f" {container_name}:{file_path} {core_dump_destination}"
                )
                os.system(cmd)


async def find_files(connection, where, name_pattern):
    """Wrapper for 'find' command over the connection"""

    try:
        process = await connection.create_process(
            ["find", where, "-maxdepth", "1", "-name", name_pattern]
        ).execute()
        return process.get_stdout().strip().split()
    except ProcessExecError:
        # Expected when 'where' doesn't exist
        return []


def copy_file(from_connection, from_path, destination_path):
    """Copy a file from within the docker container connection to the destination path"""
    if isinstance(from_connection, DockerConnection):
        container_name = container_id(from_connection.tag)

        file_name = os.path.basename(from_path)
        core_dump_destination = os.path.join(destination_path, file_name)

        cmd = (
            "docker container cp"
            f" {container_name}:{from_path} {core_dump_destination}"
        )
        print(datetime.now(), cmd)
        os.system(cmd)
    else:
        raise Exception(f"Copying files from {from_connection} is not supported")


async def get_log_without_flush(connection) -> str:
    """
    This function retrieves telio logs without flushing them. It may be needed to do that
    if log retrieval is requested after process has already exited. In such a case there is
    nothing to flush and attempting to do so will cause errors.
    """
    process = (
        connection.create_process(["type", "tcli.log"])
        if connection.target_os == TargetOS.Windows
        else connection.create_process(["cat", "./tcli.log"])
    )
    await process.execute()
    return process.get_stdout()
