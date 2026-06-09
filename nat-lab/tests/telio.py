import asyncio
import platform
import Pyro5.errors  # type: ignore
import re
import uuid
from collections import Counter
from contextlib import AsyncExitStack, asynccontextmanager
from datetime import datetime
from tests.client_analytics import ClientAnalytics
from tests.client_events import ClientEvents
from tests.client_log import ClientLog
from tests.client_tp_lite import ClientTpLite
from tests.client_vpn import ClientVpn
from tests.log_collector import LOG_COLLECTORS, LogCollector
from tests.mesh_api import Node
from tests.runtime import Events, Runtime
from tests.uniffi.libtelio_proxy import LibtelioProxy, ProxyConnectionError
from tests.utils import asyncio_util
from tests.utils.bindings import (
    Config,
    Features,
    Server,
    TelioAdapterType,
    TelioNode,
    default_features,
)
from tests.utils.connection import Connection
from tests.utils.connection_util import get_uniffi_path
from tests.utils.logger import log
from tests.utils.moose import MOOSE_DB_TIMEOUT_MS
from tests.utils.perf_profiling import PERF_CMD, PerfProfiler
from tests.utils.process import Process
from tests.utils.python import get_python_binary
from tests.utils.router import IPStack, Router, new_router
from tests.utils.router.linux_router import (
    FWMARK_VALUE as LINUX_FWMARK_VALUE,
    LinuxRouter,
)
from tests.utils.router.windows_router import WindowsRouter
from typing import AsyncIterator, List, Optional

DEVICE_STOP_TIMEOUT = 30


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
        self._log = ClientLog(self)
        self._events_facade = ClientEvents(self)
        self._vpn = ClientVpn(self)
        self._analytics = ClientAnalytics(self)
        self._tp_lite = ClientTpLite(self)
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

    @property
    def log(self) -> ClientLog:
        return self._log

    @property
    def events(self) -> ClientEvents:
        return self._events_facade

    @property
    def vpn(self) -> ClientVpn:
        return self._vpn

    @property
    def analytics(self) -> ClientAnalytics:
        return self._analytics

    @property
    def tp_lite(self) -> ClientTpLite:
        return self._tp_lite

    @asynccontextmanager
    async def run(
        self,
        meshnet_config: Optional[Config] = None,
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
                    PerfProfiler(
                        connection=self._connection,
                        file_name_suffix=self._adapter_type.name.lower(),
                    )
                )

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
            raise RuntimeError("start_named_ext_if_filter can only be used on Windows")
        await self.get_proxy().start_named_ext_if_filter(
            private_key=self._node.private_key,
            adapter=self._adapter_type,
            name=tun_name,
            ext_if_list=ext_if_filter,
        )

    async def set_meshnet_config(self, meshnet_config: Config) -> None:
        made_changes = await self.configure_interface()

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

    async def set_secret_key(self, secret_key: str):
        await self.get_proxy().set_secret_key(secret_key)

    async def enable_magic_dns(self, forward_servers: List[str]) -> None:
        # Magic DNS required adapter port.
        # For the reasoning behind this see `set_meshnet_config()`
        configured = await self.configure_interface()
        if configured and self._adapter_type == TelioAdapterType.LINUX_NATIVE_TUN:
            await asyncio.sleep(2.0)

        await self.get_proxy().enable_magic_dns(forward_servers)

    async def disable_magic_dns(self) -> None:
        await self.get_proxy().disable_magic_dns()

    async def notify_network_change(self) -> None:
        await self.get_proxy().notify_network_change()

    async def configure_interface(self) -> bool:
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
        await self.configure_interface()

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
            except (ProxyConnectionError, Pyro5.errors.CommunicationError) as e:
                # The remote can briefly become unreachable mid-test (e.g. the
                # device/VM was suspended). next_event() runs in a worker thread
                # that asyncio cannot cancel, so such a failure otherwise only
                # surfaces when this task is awaited at teardown - failing the
                # whole test's teardown (a race between this loop and the proxy
                # shutdown, LLT-5223). Treat a lost connection as transient and
                # keep retrying until the remote responds again or the task is
                # cancelled.
                if self._quit:
                    return
                log.debug(
                    "[%s] event request loop: remote unreachable, retrying (%s)",
                    self._node.name,
                    e,
                )
                await asyncio.sleep(0.5)
            except:
                if self._quit:
                    return
                raise

    async def maybe_write_device_fingerprint_to_moose_db(self):
        if self._fingerprint is not None:
            await self.log.wait_for_log("[Moose] Init callback success")
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
                                f" ('device.fp._string', '\"{fingerprint}\"', 1);"
                                " INSERT OR REPLACE INTO opt_in (id, value) VALUES (1, 1);"
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
                raise RuntimeError(
                    "Retries exhausted, while trying to write fingerprint to db"
                )

    def get_endpoint_address(self, public_key: str) -> str:
        node = self.get_node_state(public_key)
        if node is None:
            raise RuntimeError(f"Node {public_key} doesn't exist")
        if node.endpoint is None:
            raise RuntimeError(f"Node {public_key} endpoint doesn't exist")
        return node.endpoint.split(":")[0]
