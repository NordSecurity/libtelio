from typing import AsyncIterator
from contextlib import asynccontextmanager
from aiodocker import Docker
from utils.connection import Connection, DockerConnection


async def _prepare(connection: Connection) -> None:
    await connection.create_process(["conntrack", "-F"]).execute()
    await connection.create_process(
        ["iptables-save", "-f", "iptables_backup"]
    ).execute()


async def _reset(connection: Connection) -> None:
    await connection.create_process(["conntrack", "-F"]).execute()

    for table in ["filter", "nat", "mangle", "raw", "security"]:
        await connection.create_process(["iptables", "-t", table, "-F"]).execute()
    await connection.create_process(["iptables-restore", "iptables_backup"]).execute()


@asynccontextmanager
async def get(docker: Docker, container_name: str) -> AsyncIterator[DockerConnection]:
    connection = DockerConnection(await docker.containers.get(container_name))
    try:
        await _prepare(connection)
        yield connection
    finally:
        await _reset(connection)
