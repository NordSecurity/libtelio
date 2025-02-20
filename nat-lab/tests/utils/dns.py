import re
from config import LIBTELIO_DNS_IPV4
from datetime import datetime
from typing import List, Optional
from utils.connection import Connection, TargetOS


async def query_dns(
    connection: Connection,
    host_name: str,
    expected_output: Optional[List[str]] = None,
    dns_server: Optional[str] = None,
    options: Optional[List[str]] = None,
) -> None:
    # TODO(Lukas): nslookup sometimes is slow in test_dns natlab testcases.
    # It results in packets being emitted after a 1-3sec delay. To see why
    # that is happening strace is used but after investigation this should be removed.
    if connection.target_os == TargetOS.Linux:
        args = ["strace", "-tt", "nslookup"]
    else:
        args = ["nslookup"]

    if options:
        args += options
    else:
        args.append("-timeout=1")
    args.append(host_name)
    args.append(dns_server if dns_server else LIBTELIO_DNS_IPV4)
    response = await connection.create_process(args).execute()
    dns_output = response.get_stdout()
    dns_stderr = response.get_stderr()

    print(datetime.now(), "nslookup stdout:", dns_output)
    print(datetime.now(), "nslookup stderr:", dns_stderr)
    print(datetime.now(), "nslookup expected_output:", expected_output)

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
