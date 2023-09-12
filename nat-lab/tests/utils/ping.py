import asyncio
import re
from contextlib import asynccontextmanager
from ipaddress import ip_address
from typing import AsyncIterator
from utils import testing
from utils.connection import Connection, TargetOS
from utils.process import Process
from utils.router import IPProto, get_ip_address_type

# This utility uses the standard OS provided `ping` binaries.
# It should work for Linux, Windows and Mac.

# fmt: off
IPV4SEG  = r'(?:25[0-5]|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9])'
IPV4ADDR = r'(?:(?:' + IPV4SEG + r'\.){3,3}' + IPV4SEG + r')'
IPV6SEG  = r'(?:(?:[0-9a-fA-F]){1,4})'
IPV6GROUPS = (
    r'(?:' + IPV6SEG + r':){7,7}' + IPV6SEG,                  # 1:2:3:4:5:6:7:8
    r'(?:' + IPV6SEG + r':){1,7}:',                           # 1::, 1:2:3:4:5:6:7::
    r'(?:' + IPV6SEG + r':){1,6}:' + IPV6SEG,                 # 1::8, 1:2:3:4:5:6::8, 1:2:3:4:5:6::8
    r'(?:' + IPV6SEG + r':){1,5}(?::' + IPV6SEG + r'){1,2}',  # 1::7:8, 1:2:3:4:5::7:8, :2:3:4:5::8
    r'(?:' + IPV6SEG + r':){1,4}(?::' + IPV6SEG + r'){1,3}',  # 1::6:7:8, 1:2:3:4::6:7:8, 1:2:3:4::8
    r'(?:' + IPV6SEG + r':){1,3}(?::' + IPV6SEG + r'){1,4}',  # 1::5:6:7:8, 1:2:3::5:6:7:8, 1:2:3::8
    r'(?:' + IPV6SEG + r':){1,2}(?::' + IPV6SEG + r'){1,5}',  # 1::4:5:6:7:8, 1:2::4:5:6:7:8, 1:2::8
    IPV6SEG + r':(?:(?::' + IPV6SEG + r'){1,6})',             # 1::3:4:5:6:7:8, 1::3:4:5:6:7:8, 1::8
    r':(?:(?::' + IPV6SEG + r'){1,7}|:)',                     # ::2:3:4:5:6:7:8, ::2:3:4:5:6:7:8, ::8, ::
    r'fe80:(?::' + IPV6SEG + r'){0,4}%[0-9a-zA-Z]{1,}',       # fe80::7:8%eth0, fe80::7:8%1 (link-local IPv6 addresses with zone index)
    r'::(?:ffff(?::0{1,4}){0,1}:){0,1}[^\s:]' + IPV4ADDR,     # ::255.255.255.255, ::ffff:255.255.255.255, ::ffff:0:255.255.255.255 (IPv4-mapped IPv6 addresses and IPv4-translated addresses)
    r'(?:' + IPV6SEG + r':){1,6}:?[^\s:]' + IPV4ADDR          # 2001:db8:3:4::192.0.2.33, 64:ff9b::192.0.2.33 (IPv4-Embedded IPv6 Address)
)
IPV6ADDR = '|'.join(['(?:{})'.format(g) for g in IPV6GROUPS[::-1]])  # pylint: disable=consider-using-f-string
# fmt: on


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
                result = re.findall(IPV6ADDR, line)
                if result and (ip_address(result[0]) == ip_address(self._ip)):
                    self._next_ping_event.set()
            else:
                if line.find(f"from {self._ip}") > 0:
                    self._next_ping_event.set()

    async def execute(self) -> None:
        await self._process.execute(stdout_callback=self.on_stdout)

    async def wait_for_next_ping(self) -> None:
        self._next_ping_event.clear()
        await self._next_ping_event.wait()
        self._next_ping_event.clear()

    @asynccontextmanager
    async def run(self) -> AsyncIterator["Ping"]:
        async with self._process.run(stdout_callback=self.on_stdout):
            yield self
