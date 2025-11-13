import asyncio
import re
import secrets
import logging
from utils.logger import log
import datetime
from contextlib import asynccontextmanager
from ipaddress import ip_address
from typing import AsyncIterator, Optional
from utils import testing
from utils.connection import Connection, TargetOS
from utils.process import Process, ProcessExecError
from utils.router import IPProto, REG_IPV6ADDR, get_ip_address_type


async def ping(
    connection: Connection, ip: str, timeout: Optional[float] = None
) -> None:
    async with Ping(connection, ip).run() as ping_process:
        await asyncio.create_task(
            ping_process.wait_for_any_ping(timeout),
            name=f"ping({connection}, {ip}, {timeout})",
        )


async def ping_once(connection: Connection, ip: str) -> None:
    ip_proto = testing.unpack_optional(get_ip_address_type(ip))

    if connection.target_os == TargetOS.Windows:
        cmd = [
            "ping",
            "-4" if ip_proto == IPProto.IPv4 else "-6",
            "-n",
            "1",
            "-w",
            "1000",
            ip,
        ]
    elif connection.target_os == TargetOS.Mac:
        cmd = [
            "ping" if ip_proto == IPProto.IPv4 else "ping6",
            "-c",
            "1",
            "-W",
            "1",
            ip,
        ]
    else:
        cmd = [
            "ping",
            "-4" if ip_proto == IPProto.IPv4 else "-6",
            "-c",
            "1",
            "-W",
            "1",
            ip,
        ]

    proc = connection.create_process(cmd, quiet=True)
    try:
        await proc.execute()
    except ProcessExecError as e:
        out = proc.get_stdout().lower()
        print("================= ", datetime.datetime.now())
        print(proc.get_stdout())
        print(proc.get_stderr())
        print("=================")

        if (
            "1 packets transmitted" in out
            or "1 packet transmitted" in out
            or "sent = 1" in out
        ):
            return

        raise e


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
        kill_id = secrets.token_hex(8).upper()

        if connection.target_os == TargetOS.Windows:
            self._process = connection.create_process(
                ["ping", ("-4" if self._ip_proto == IPProto.IPv4 else "-6"), "-t", ip],
                quiet=True,
            )
        elif connection.target_os == TargetOS.Mac:
            self._process = connection.create_process(
                [
                    ("ping" if self._ip_proto == IPProto.IPv4 else "ping6"),
                    "-p",
                    kill_id,
                    ip,
                ],
                quiet=True,
            )
        else:
            self._process = connection.create_process(
                [
                    "ping",
                    ("-4" if self._ip_proto == IPProto.IPv4 else "-6"),
                    "-p",
                    kill_id,
                    ip,
                ],
                kill_id,
                quiet=True,
            )
        self._next_ping_event = asyncio.Event()

    async def on_stdout(self, stdout: str) -> None:
        for line in stdout.splitlines():
            log.debug(f"ping: {self._connection.tag} -> {self._ip}: {line}")
            log.warning(f"ping: {self._connection.tag} -> {self._ip}: {line}")
            print(
                f"{datetime.datetime.now()} ping: {self._connection.tag} -> {self._ip}: {line}"
            )
            if self._ip_proto == IPProto.IPv6:
                result = re.findall(REG_IPV6ADDR, line)
                if result and (ip_address(result[0]) == ip_address(self._ip)):
                    self._next_ping_event.set()
            else:
                if line.find(f"from {self._ip}") > 0:
                    self._next_ping_event.set()

    async def execute(self) -> None:
        print(
            f"{datetime.datetime.now()} ping: execute {self._connection.tag} -> {self._ip}"
        )
        await self._process.execute(
            stdout_callback=self.on_stdout, stderr_callback=self.on_stdout
        )

    async def wait_for_next_ping(self, timeout: Optional[float] = None) -> None:
        self._next_ping_event.clear()
        await asyncio.wait_for(self._next_ping_event.wait(), timeout)
        self._next_ping_event.clear()

    async def wait_for_any_ping(self, timeout: Optional[float] = None) -> None:
        await asyncio.wait_for(self._next_ping_event.wait(), timeout)
        self._next_ping_event.clear()

    @asynccontextmanager
    async def run(self) -> AsyncIterator["Ping"]:
        print(
            f"{datetime.datetime.now()} ping: run {self._connection.tag} -> {self._ip}"
        )
        async with self._process.run(
            stdout_callback=self.on_stdout, stderr_callback=self.on_stdout
        ):
            yield self
