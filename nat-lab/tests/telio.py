from utils.connection import Connection, TargetOS
from utils.process import Process
from utils import asyncio_util
from contextlib import asynccontextmanager
from dataclasses import dataclass
from dataclasses_json import dataclass_json, DataClassJsonMixin
from enum import Enum
from mesh_api import Node
from typing import List, Dict, Any, Set, Optional, AsyncIterator
from utils import Router, new_router, OutputNotifier, connection_util
from config import DERP_PRIMARY
import asyncio
import json
import os
import re
import shlex
import utils.testing as testing
from collections import Counter
from telio_features import TelioFeatures


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
    conn_state: str


# Equivalent of `libtelio/telio-wg/src/uapi.rs`
class State(Enum):
    Disconnected = "disconnected"
    Connecting = "connecting"
    Connected = "connected"


# Equivalent of `libtelio/crates/telio-model/src/api_config.rs:PathType`
class PathType(Enum):
    Relay = "relay"
    Direct = "direct"

    # Any should always be last, because it is only introduced in nat-lab, not in libtelio itself
    Any = "any"


# Equivalent of `libtelio/crates/telio-model/src/mesh.rs:Node`
@dataclass_json
@dataclass
class PeerInfo(DataClassJsonMixin):
    identifier: str
    public_key: str
    state: State
    is_exit: bool
    is_vpn: bool
    ip_addresses: List[str]
    allowed_ips: List[str]
    endpoint: Optional[str]
    hostname: Optional[str]
    allow_incoming_connections: bool
    allow_peer_send_files: bool
    path: PathType

    def __init__(
        self,
        identifier="",
        public_key="",
        state=State.Disconnected,
        is_exit=False,
        is_vpn=False,
        ip_addresses=[],
        allowed_ips=[],
        endpoint=None,
        hostname=None,
        allow_incoming_connections=False,
        allow_peer_send_files=False,
        path=PathType.Relay,
    ):
        self.identifier = identifier
        self.public_key = public_key
        self.state = state
        self.is_exit = is_exit
        self.is_vpn = is_vpn
        self.ip_addresses = ip_addresses
        self.allowed_ips = allowed_ips
        self.endpoint = endpoint
        self.hostname = hostname
        self.allow_incoming_connections = allow_incoming_connections
        self.allow_peer_send_files = allow_peer_send_files
        self.path = path


# Equivalent of `libtelio/telio-wg/src/adapter/mod.rs`
class AdapterType(Enum):
    Default = ""
    BoringTun = "boringtun"
    LinuxNativeWg = "linux-native"
    WireguardGo = "wireguard-go"
    WindowsNativeWg = "wireguard-nt"


class Runtime:
    _output_notifier: OutputNotifier
    _peer_info: Dict[str, PeerInfo]
    _peer_state_events: Dict[str, List[asyncio.Event]]
    _derp_state: Optional[DerpServer]
    _peer_sent_cmm_responses: List[str]
    _pinged_endpoints: List[str]
    _started_tasks: List[str]
    _stopped_tasks: List[str]
    allowed_pub_keys: Set[str]

    def __init__(self) -> None:
        self._output_notifier = OutputNotifier()
        self._peer_info = {}
        self._peer_state_events = {}
        self._derp_state = None
        self._peer_sent_cmm_responses = []
        self._pinged_endpoints = []
        self._started_tasks = []
        self._stopped_tasks = []
        self.allowed_pub_keys = set()

    def _handle_derp_status(self, line) -> bool:
        if not line.startswith("- derp status: "):
            return False

        tokens = line.split("- derp status: ")
        json_string = tokens[1].strip()

        result = re.search("{(.*)}", json_string)
        if result:
            derp_state = DerpServer.schema().loads("{" + result.group(1) + "}")
            assert type(derp_state) == DerpServer
            self._derp_state = derp_state
            return True

        self._derp_state = None
        return False

    def _handle_sent_cmm_responses(self, line) -> bool:
        if "send cmm response to peer" not in line:
            return False

        tokens = line.split("send cmm response to peer")
        string = tokens[1].strip()
        result = re.search(r"\[(.*?)\]", string)

        if result:
            self._peer_sent_cmm_responses.append(result.group(1))
            return True

        return False

    def _handle_pinged_endpoints(self, line) -> bool:
        if "ping endpoint" not in line:
            return False

        tokens = line.split("ping endpoint")
        string = tokens[1].strip()
        result = re.search(r"\[(.*?)\]", string)

        if result:
            tokens = result.group(1).split(":")
            self._pinged_endpoints.append(tokens[0])
            return True

        return False

    def handle_output_line(self, line) -> bool:
        return (
            self._handle_node_event(line)
            or self._output_notifier.handle_output(line)
            or self._handle_derp_status(line)
            or self._handle_relay_event(line)
            or self._handle_sent_cmm_responses(line)
            or self._handle_pinged_endpoints(line)
            or self._handle_task_information(line)
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

    def notify_peer_state(self, public_key: str, event: asyncio.Event) -> None:
        if public_key not in self._peer_state_events:
            self._peer_state_events[public_key] = [event]
        else:
            self._peer_state_events[public_key].append(event)

    def get_peer_info(self, public_key: str) -> Optional[PeerInfo]:
        return self._peer_info.get(public_key)

    def _handle_node_event(self, line) -> bool:
        if not line.startswith("event node: "):
            return False

        tokens = line.split("event node: ")
        json_string = tokens[1].strip()
        result = re.search("{(.*)}", json_string)

        if result:
            node_state = PeerInfo.schema().loads(
                "{" + result.group(1).replace("\\", "") + "}"
            )
            assert type(node_state) == PeerInfo
            self._peer_info[node_state.public_key] = node_state
            self._set_peer_state(
                node_state.public_key,
                node_state.state,
                node_state.path,
            )
            return True
        return False

    def _set_peer_state(
        self, public_key: str, state: State, path=PathType.Relay
    ) -> None:
        if public_key not in self._peer_info:
            self._peer_info[public_key] = PeerInfo()

        self._peer_info[public_key].state = state
        self._peer_info[public_key].path = path
        assert public_key in self.allowed_pub_keys
        events = self._peer_state_events.pop(public_key, None)
        if events:
            for event in events:
                event.set()

    def _handle_relay_event(self, line) -> bool:
        if not line.startswith("event relay: "):
            return False

        result = re.search("^event relay: {(.*)}", line)
        if result:
            derp_server_json = DerpServer.schema().loads("{" + result.group(1) + "}")
            assert type(derp_server_json) == DerpServer
            self._derp_state = derp_server_json
            return True
        return False


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

    async def wait_for_state(
        self,
        public_key: str,
        state: State,
        path: PathType = PathType.Relay,
        wait_for_repeating_event: bool = False,
    ) -> None:
        peer_info = self._runtime.get_peer_info(public_key)
        if (
            peer_info
            and wait_for_repeating_event is False
            and peer_info.state == state
            and (peer_info.path == path or path == PathType.Any)
        ):
            return

        while True:
            event = asyncio.Event()
            self._runtime.notify_peer_state(public_key, event)
            await event.wait()
            peer_info = self._runtime.get_peer_info(public_key)
            if (
                peer_info
                and peer_info.state == state
                and (peer_info.path == path or path == PathType.Any)
            ):
                return


class Client:
    def __init__(
        self,
        router: Router,
        node: Node,
        events: Events,
        process: Process,
        runtime: Runtime,
    ) -> None:
        self._router = router
        self._node = node
        self._events = events
        self._process = process
        self._runtime = runtime
        self._interface_configured = False
        self._message_idx = 0
        self._adapter_type: Optional[AdapterType] = None

    async def start(self, adapter_type: AdapterType) -> None:
        self._adapter_type = adapter_type

        await self._write_command(
            [
                "dev",
                "start",
                adapter_type.value,
                self._router.get_interface_name(),
                self._node.private_key,
            ],
        )

        self.future_event_request_loop = asyncio_util.run_async(
            self._event_request_loop()
        )

    async def simple_start(self):
        assert self._adapter_type is not None
        await self._write_command(
            [
                "dev",
                "start",
                self._adapter_type.value,
                self._router.get_interface_name(),
                self._node.private_key,
            ],
        )

    async def get_sent_cmm_responses(self) -> List[str]:
        return self._runtime._peer_sent_cmm_responses

    async def get_pinged_endpoints(self) -> List[str]:
        return self._runtime._pinged_endpoints

    async def handshake(
        self, public_key, path=PathType.Relay, wait_for_repeating_event: bool = False
    ) -> None:
        await self._events.wait_for_state(
            public_key,
            State.Connected,
            path,
            wait_for_repeating_event,
        )

    async def disconnect(self, public_key, path=PathType.Relay) -> None:
        await self._events.wait_for_state(public_key, State.Disconnected, path)

    async def connecting(self, public_key, path=PathType.Relay) -> None:
        await self._events.wait_for_state(public_key, State.Connecting, path)

    async def wait_for_any_node_event(self, public_key) -> None:
        event = asyncio.Event()
        self._runtime.notify_peer_state(public_key, event)
        await event.wait()

    async def set_meshmap(self, meshmap: Dict[str, Any]) -> None:
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
                self._runtime.allowed_pub_keys.add(peer["public_key"])

        await self._write_command(["mesh", "config", json.dumps(meshmap)])

    async def set_mesh_off(self):
        await self._write_command(["mesh", "off"])

    async def receive_ping(self):
        await self._write_command(["mesh", "ping"])

    async def send_stun(self):
        await self._write_command(["mesh", "stun"])

    async def igd(self):
        await self._write_command(["mesh", "igd"])

    async def connect_to_vpn(self, ip, port, public_key) -> None:
        await self._configure_interface()
        await self._router.create_vpn_route()
        self._runtime.allowed_pub_keys.add(public_key)
        await self._write_command(
            [
                "dev",
                "con",
                public_key,
                "{}:{}".format(ip, port),
            ],
        )

    async def disconnect_from_vpn(self, public_key, path=PathType.Relay) -> None:
        await self._write_command(["vpn", "off"])
        await self.disconnect(public_key, path)
        await self._router.delete_vpn_route()

    async def disconnect_from_exit_nodes(self) -> None:
        await self._write_command(["vpn", "off"])
        await self._router.delete_vpn_route()

    async def enable_magic_dns(self, forward_servers: List[str]) -> None:
        await self._write_command(
            ["dns", "on"] + forward_servers,
        )

    async def disable_magic_dns(self) -> None:
        await self._write_command(
            ["dns", "off"],
        )

    async def notify_network_change(self) -> None:
        await self._write_command(
            ["dev", "notify-net-change"],
        )

    async def _configure_interface(self) -> bool:
        if not self._interface_configured:
            await self._router.setup_interface(
                self._node.ip_addresses[0],
            )

            await self._router.create_meshnet_route()
            self._interface_configured = True
            return True

        return False

    async def connect_to_exit_node(self, public_key: str) -> None:
        await self._configure_interface()
        await self._router.create_vpn_route()
        await self._write_command(["dev", "con", public_key])

    def get_router(self) -> Router:
        return self._router

    async def stop_device(self) -> None:
        await self._write_command(["dev", "stop"])
        self._interface_configured = False
        assert Counter(self._runtime._started_tasks) == Counter(
            self._runtime._stopped_tasks
        ), f"started tasks and stopped tasks differ!"

    def get_node_state(self, public_key: str) -> Optional[PeerInfo]:
        return self._runtime.get_peer_info(public_key)

    async def get_derp_server(self) -> Optional[DerpServer]:
        return self._runtime._derp_state

    async def _event_request_loop(self) -> None:
        while True:
            await self._write_command(["events"])
            await asyncio.sleep(1)

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

        await self._write_command(
            [
                "derp",
                "on",
                sk,
                derp01_server,
                allowed_pk,
            ]
        )

    async def disconnect_fake_derprelay(self) -> None:
        await self._write_command(["derp", "off"])

    async def recv_message_from_fake_derp_relay(self) -> None:
        await self._write_command(["derp", "recv"])

    async def fake_derp_events(self) -> None:
        await self._write_command(["derp", "events"])

    async def send_message_from_fake_derp_relay(self, pk: str, data: List[str]) -> None:
        await self._write_command(["derp", "send", pk] + data)

    async def _write_command(self, command: List[str]) -> None:
        idx = self._message_idx
        cmd = (
            f"MESSAGE_ID={str(idx)} "
            + " ".join([shlex.quote(arg) for arg in command])
            + "\n"
        )
        await self._process.write_stdin(cmd)
        self._message_idx += 1
        await self._events.message_done(idx)


@asynccontextmanager
async def run_meshnet(
    connection: Connection,
    node: Node,
    meshmap: Dict[str, Any],
    adapter_type=AdapterType.Default,
    telio_features=TelioFeatures(),
) -> AsyncIterator[Client]:
    async with run(connection, node, adapter_type, telio_features) as client:
        await client.set_meshmap(meshmap)
        yield client


@asynccontextmanager
async def run(
    connection: Connection,
    node: Node,
    adapter_type=AdapterType.Default,
    telio_features=TelioFeatures(),
) -> AsyncIterator[Client]:
    runtime = Runtime()

    async def on_stdout(stdout: str) -> None:
        supress_print_list = [
            "MESSAGE_DONE=",
            "- no login.",
            "- telio running.",
            "- telio nodes",
            "- derp status",
            "task stopped - ",
            "task started - ",
            "send cmm response to peer",
            "ping endpoint",
        ]
        for line in stdout.splitlines():
            if not any(string in line for string in supress_print_list):
                print(f"[{node.name}]: {line}")
            runtime.handle_output_line(line)

    tcli_path = connection_util.get_libtelio_binary_path("tcli", connection)
    features = "-f " + telio_features.to_json()

    process = connection.create_process(
        [
            tcli_path,
            "--less-spam",
            features,
        ]
    )
    future_process = asyncio_util.run_async(process.execute(stdout_callback=on_stdout))
    await process.wait_stdin_ready()

    client = Client(new_router(connection), node, Events(runtime), process, runtime)
    await client.start(adapter_type)

    try:
        yield client
    finally:
        await testing.wait_normal(client.stop_device())
        await asyncio_util.cancel_future(future_process)
        await asyncio_util.cancel_future(client.future_event_request_loop)
        await save_logs(connection)


async def save_logs(connection: Connection) -> None:
    if os.environ.get("NATLAB_SAVE_LOGS") is None:
        return

    log_dir = "logs"
    os.makedirs(log_dir, exist_ok=True)

    process = (
        connection.create_process(["type", "tcli.log"])
        if connection.target_os == TargetOS.Windows
        else connection.create_process(["cat", "./tcli.log"])
    )
    await process.execute()
    log_content = process.get_stdout()

    if connection.target_os == TargetOS.Linux:
        process = connection.create_process(["cat", "/etc/hostname"])
        await process.execute()
        container_id = process.get_stdout().strip()
    else:
        container_id = str(connection.target_os)

    test_name = os.environ.get("PYTEST_CURRENT_TEST")
    if test_name is not None:
        test_name = "".join(
            [x if x.isalnum() else "_" for x in test_name.split(" ")[0]]
        )
    with open(
        os.path.join(log_dir, str(test_name) + "_" + container_id + ".log"), "w"
    ) as f:
        f.write(log_content)
