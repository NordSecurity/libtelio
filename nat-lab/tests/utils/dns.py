import re
from tests.config import LIBTELIO_DNS_IPV4
from tests.utils.connection import Connection
from tests.utils.logger import log
from typing import List, Optional


async def query_dns(
    connection: Connection,
    host_name: str,
    expected_output: Optional[List[str]] = None,
    dns_server: Optional[str] = None,
    options: Optional[List[str]] = None,
) -> None:
    args = ["nslookup"]
    if options:
        args += options
    else:
        args.append("-timeout=1")
    args.append("-retry=5")
    args.append(host_name)
    args.append(dns_server if dns_server else LIBTELIO_DNS_IPV4)
    response = await connection.create_process(args).execute()
    dns_output = response.get_stdout()
    log.info("nslookup stdout: %s", dns_output)
    log.info("nslookup expected_output: %s", expected_output)
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
