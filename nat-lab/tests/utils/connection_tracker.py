import re
import asyncio
import time
import config
import utils
from typing import Optional, List, Dict, AsyncIterator
from dataclasses import dataclass
from utils.ping import Ping
from utils.connection import Connection
from utils.process import Process
from contextlib import asynccontextmanager


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

    match = re.search(r"\[NEW\] (\w+)", input_string)
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
        self._config: Optional[List[ConnectionTrackerConfig]] = config
        self._events: List[FiveTuple] = []
        self._last_event: Optional[FiveTuple] = None
        self._events_wait_list: Dict[str, List[asyncio.Event]] = {}

        self._initialized: bool = False
        self._init_connection: FiveTuple = FiveTuple(
            protocol="icmp", dst_ip="127.0.0.1"
        )

    async def on_stdout(self, stdout: str) -> None:
        if not self._config:
            return

        for line in stdout.splitlines():
            connection = parse_input(line)
            if connection is FiveTuple():
                continue

            if not self._initialized:
                if self._init_connection.partial_eq(connection):
                    self._initialized = True
                    continue

            matching_configs = [
                cfg for cfg in self._config if cfg.target.partial_eq(connection)
            ]
            if not matching_configs:
                continue

            self._events.append(connection)
            self._last_event = connection

            for cfg in matching_configs:
                if events := self._events_wait_list.pop(cfg.key, None):
                    for event in events:
                        event.set()

    async def execute(self) -> None:
        if not self._config:
            return

        await self._process.execute(stdout_callback=self.on_stdout)

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
            raise KeyError(f"Key {key} doesn't exist in config")

        if self._last_event:
            if cfg.target.partial_eq(self._last_event):
                return

        event = asyncio.Event()
        if key not in self._events_wait_list:
            self._events_wait_list[key] = [event]
        else:
            self._events_wait_list[key].append(event)
        await event.wait()

    @asynccontextmanager
    async def run(self) -> AsyncIterator["ConnectionTracker"]:
        async with self._process.run(stdout_callback=self.on_stdout):
            await self._process.wait_stdin_ready()
            # initialization is just waiting for first conntrack event,
            # since it has no other indication if it is truly running.
            # Or wait for 1 second and pray it was initialized
            async with Ping(self._connection, "127.0.0.1").run():
                start_time = time.time()
                while not self._initialized:
                    if time.time() - start_time >= 1:
                        self._initialized = True
                        break
                    await asyncio.sleep(0.1)

            yield self


def generate_connection_tracker_config(
    connection_tag,
    vpn_1_limits: ConnectionLimits = ConnectionLimits(0, 0),
    vpn_2_limits: ConnectionLimits = ConnectionLimits(0, 0),
    stun_limits: ConnectionLimits = ConnectionLimits(0, 0),
    ping_limits: ConnectionLimits = ConnectionLimits(0, 0),
    derp_0_limits: ConnectionLimits = ConnectionLimits(0, 0),
    derp_1_limits: ConnectionLimits = ConnectionLimits(0, 0),
    derp_2_limits: ConnectionLimits = ConnectionLimits(0, 0),
    derp_3_limits: ConnectionLimits = ConnectionLimits(0, 0),
) -> List[ConnectionTrackerConfig]:
    lan_addr = utils.LAN_ADDR_MAP[connection_tag]
    return [
        ConnectionTrackerConfig(
            "vpn_1",
            vpn_1_limits,
            FiveTuple(
                protocol="udp",
                src_ip=lan_addr,
                dst_ip=str(config.WG_SERVER.get("ipv4")),
                dst_port=51820,
            ),
        ),
        ConnectionTrackerConfig(
            "vpn_2",
            vpn_2_limits,
            FiveTuple(
                protocol="udp",
                src_ip=lan_addr,
                dst_ip=str(config.WG_SERVER_2.get("ipv4")),
                dst_port=51820,
            ),
        ),
        ConnectionTrackerConfig(
            "stun",
            stun_limits,
            FiveTuple(
                protocol="udp",
                src_ip=lan_addr,
                dst_ip=config.STUN_SERVER,
                dst_port=3478,
            ),
        ),
        ConnectionTrackerConfig(
            "ping",
            ping_limits,
            FiveTuple(
                protocol="icmp",
            ),
        ),
        ConnectionTrackerConfig(
            "derp_0",
            derp_0_limits,
            FiveTuple(
                protocol="tcp",
                src_ip=lan_addr,
                dst_ip=str(config.DERP_FAKE.get("ipv4")),
                dst_port=8765,
            ),
        ),
        ConnectionTrackerConfig(
            "derp_1",
            derp_1_limits,
            FiveTuple(
                protocol="tcp",
                src_ip=lan_addr,
                dst_ip=str(config.DERP_PRIMARY.get("ipv4")),
                dst_port=8765,
            ),
        ),
        ConnectionTrackerConfig(
            "derp_2",
            derp_2_limits,
            FiveTuple(
                protocol="tcp",
                src_ip=lan_addr,
                dst_ip=str(config.DERP_SECONDARY.get("ipv4")),
                dst_port=8765,
            ),
        ),
        ConnectionTrackerConfig(
            "derp_3",
            derp_3_limits,
            FiveTuple(
                protocol="tcp",
                src_ip=lan_addr,
                dst_ip=str(config.DERP_TERTIARY.get("ipv4")),
                dst_port=8765,
            ),
        ),
    ]
