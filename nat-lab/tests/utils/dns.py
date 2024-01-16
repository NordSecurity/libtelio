import re
from config import LIBTELIO_DNS_IPV4
from typing import List, Optional
from utils import testing
from utils.connection import Connection


async def query_dns(
    connection: Connection,
    host_name: str,
    expected_output: Optional[List[str]] = None,
    dns_server: Optional[str] = None,
    options: Optional[str] = None,
) -> None:
    response = await testing.wait_long(
        connection.create_process(
            [
                "nslookup",
                options if options else "-timeout=1",
                host_name,
                dns_server if dns_server else LIBTELIO_DNS_IPV4,
            ]
        ).execute()
    )
    dns_output = response.get_stdout()
    if expected_output:
        for expected_str in expected_output:
            assert re.search(expected_str, dns_output, re.DOTALL) is not None
