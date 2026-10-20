import re
from tests.config import LIBTELIO_DNS_IPV4
from tests.utils.connection import Connection
from tests.utils.logger import log
from tests.utils.process import ProcessExecError
from typing import List, Optional


async def query_dns(
    connection: Connection,
    host_name: str,
    expected_output: Optional[List[str]] = None,
    dns_server: Optional[str] = None,
    options: Optional[List[str]] = None,
    quiet: bool = False,
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
    if not quiet:
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
    unexpected_output: Optional[List[str]] = None,
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
    if unexpected_output:
        for unexpected_str in unexpected_output:
            assert re.search(unexpected_str, dns_output, re.DOTALL) is None


async def assert_no_dns_reply(
    connection: Connection,
    host_name: str,
    dns_server: str,
    extra_host_options: Optional[List[str]] = None,
    timeout: int = 3,
) -> None:
    cmd = [
        "dig",
        "+tries=1",
        f"+timeout={timeout}",
        "@" + dns_server,
        "-p",
        "53",
        host_name,
    ]
    if extra_host_options:
        cmd += extra_host_options

    try:
        response = await connection.create_process(cmd).execute()
    except ProcessExecError as e:
        assert re.search("no servers could be reached", e.stdout), e.stdout
        # Refused connections also end with "no servers could be reached"
        assert "timed out" in e.stdout, e.stdout
        assert "status:" not in e.stdout, e.stdout
        return
    assert False, f"Expected no DNS reply, got: {response.get_stdout()}"
