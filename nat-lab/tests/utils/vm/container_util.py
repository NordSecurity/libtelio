from aiodocker import Docker
from contextlib import asynccontextmanager
from typing import AsyncIterator
from utils.connection import Connection, DockerConnection
from utils.router.linux_router import INTERFACE_NAME


async def _prepare(connection: Connection, remove_existing_interfaces: bool) -> None:
    await connection.create_process(["conntrack", "-F"]).execute()
    await connection.create_process(
        ["iptables-save", "-f", "iptables_backup"]
    ).execute()
    await connection.create_process(
        ["ip6tables-save", "-f", "ip6tables_backup"]
    ).execute()
    if remove_existing_interfaces:
        try:
            await connection.create_process(
                ["ip", "link", "delete", INTERFACE_NAME]
            ).execute()
        except:
            pass  # Most of the time there will be no interface to be deleted


async def _reset(connection: Connection) -> None:
    await connection.create_process(["conntrack", "-F"]).execute()

    for table in ["filter", "nat", "mangle", "raw", "security"]:
        await connection.create_process(["iptables", "-t", table, "-F"]).execute()
        await connection.create_process(["ip6tables", "-t", table, "-F"]).execute()
    await connection.create_process(["iptables-restore", "iptables_backup"]).execute()
    await connection.create_process(["ip6tables-restore", "ip6tables_backup"]).execute()


@asynccontextmanager
async def get(
    docker: Docker, container_name: str, remove_existing_interfaces: bool = True
) -> AsyncIterator[DockerConnection]:
    connection = DockerConnection(
        await docker.containers.get(container_name), container_name
    )
    try:
        await _prepare(connection, remove_existing_interfaces)
        yield connection
    finally:
        await _reset(connection)
