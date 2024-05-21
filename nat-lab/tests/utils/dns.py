import re
from config import LIBTELIO_DNS_IPV4
from typing import List, Optional
from utils.connection import Connection


async def query_dns(
    connection: Connection,
    host_name: str,
    expected_output: Optional[List[str]] = None,
    dns_server: Optional[str] = None,
    options: Optional[str] = None,
) -> None:
    response = await connection.create_process([
        "nslookup",
        options if options else "-timeout=1",
        host_name,
        dns_server if dns_server else LIBTELIO_DNS_IPV4,
    ]).execute()
    dns_output = response.get_stdout()
    if expected_output:
        for expected_str in expected_output:
            assert re.search(expected_str, dns_output, re.DOTALL) is not None


async def query_dns_port(
    connection: Connection,
    port: str,
    host_name: str,
    dns_server: str,
    expected_output: Optional[List[str]] = None,
    options: Optional[str] = None,
    extra_host_options: Optional[List[str]] = None,
) -> None:
    cmd = [
        "dig",
        options if options else "+timeout=1",
        "@" + dns_server,
        "-p",
        port,
        host_name,
    ]
    if extra_host_options:
        cmd += list(extra_opt for extra_opt in extra_host_options)

    response = await connection.create_process(cmd).execute()
    dns_output = response.get_stdout()
    if expected_output:
        for expected_str in expected_output:
            assert re.search(expected_str, dns_output, re.DOTALL) is not None
