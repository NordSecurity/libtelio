import asyncio
import re
import timeouts
from contextlib import asynccontextmanager
from ipaddress import ip_address
from typing import AsyncIterator
from utils import testing
from utils.connection import Connection, TargetOS
from utils.process import Process
from utils.router import IPProto, REG_IPV6ADDR, get_ip_address_type

# This utility uses the standard OS provided `ping` binaries.
# It should work for Linux, Windows and Mac.


class Ping:
    _ip: str
    _ip_proto: IPProto
    _process: Process
    _next_ping_event: asyncio.Event
    _connection: Connection

    def __init__(self, connection: Connection, ip: str) -> None:
        self._ip = ip
        self._connection = connection
        self._ip_proto = testing.unpack_optional(get_ip_address_type(ip))

        if connection.target_os == TargetOS.Windows:
            self._process = connection.create_process(
                ["ping", ("-4" if self._ip_proto == IPProto.IPv4 else "-6"), "-t", ip]
            )
        elif connection.target_os == TargetOS.Mac:
            self._process = connection.create_process(
                [("ping" if self._ip_proto == IPProto.IPv4 else "ping6"), ip]
            )
        else:
            self._process = connection.create_process(
                ["ping", ("-4" if self._ip_proto == IPProto.IPv4 else "-6"), ip]
            )
        self._next_ping_event = asyncio.Event()

    async def on_stdout(self, stdout: str) -> None:
        for line in stdout.splitlines():
            if self._ip_proto == IPProto.IPv6:
                result = re.findall(REG_IPV6ADDR, line)
                if result and (ip_address(result[0]) == ip_address(self._ip)):
                    self._next_ping_event.set()
            else:
                if line.find(f"from {self._ip}") > 0:
                    self._next_ping_event.set()

    async def execute(self) -> None:
        await self._process.execute(stdout_callback=self.on_stdout)

    async def wait_for_next_ping(
        self, timeout: float = timeouts.DEFAULT_PING_EVENT_TIMEOUT
    ) -> None:
        self._next_ping_event.clear()
        await asyncio.wait_for(self._next_ping_event.wait(), timeout)
        self._next_ping_event.clear()

    @asynccontextmanager
    async def run(self) -> AsyncIterator["Ping"]:
        async with self._process.run(stdout_callback=self.on_stdout):
            yield self
