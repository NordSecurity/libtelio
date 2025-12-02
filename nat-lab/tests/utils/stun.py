import asyncio
import re
from tests.config import STUN_BINARY_PATH_WINDOWS, STUN_BINARY_PATH_MAC
from tests.utils import testing
from tests.utils.connection import Connection, TargetOS
from tests.utils.router import IPProto, REG_IPV6ADDR, get_ip_address_type
from typing import Optional

# For Linux, use the standard `stunclient` available on most distributions.
#
# For Windows, stun binaries are available from
# http://www.stunprotocol.org/
#
# For Mac, stun binaries are available from
# https://master.dl.sourceforge.net/project/stuntman/stunserver_osx_1_2_13.zip?viasf=1


async def get(
    connection: Connection,
    stun_server: str,
    stun_server_port: int = 3478,
    timeout: Optional[float] = None,
) -> str:
    ip_proto = testing.unpack_optional(get_ip_address_type(stun_server))

    path = ""

    if connection.target_os == TargetOS.Windows:
        assert (
            stun_server_port == 3478
        ), "Non-standard Stun ports are supported only on Linux"

        path = STUN_BINARY_PATH_WINDOWS

    elif connection.target_os == TargetOS.Mac:
        assert (
            stun_server_port == 3478
        ), "Non-standard Stun ports are supported only on Linux"

        path = STUN_BINARY_PATH_MAC

    elif connection.target_os == TargetOS.Linux:
        path = "stunclient"
    else:
        assert False, "unsupported os"

    process = await asyncio.wait_for(
        connection.create_process(
            [
                path,
                stun_server,
                "--family",
                ("4" if ip_proto == IPProto.IPv4 else "6"),
                "--verbosity",
                "2",
            ],
            quiet=True,
        ).execute(),
        timeout,
    )

    # Match: 'Mapped address: 10.0.254.1:24295' or 'Mapped address: 2001:db8:85a4::dead:beef:ceed.44947'
    match = re.search(
        (
            r"Mapped address: (\d+\.\d+\.\d+\.\d+):(\d+)"
            if ip_proto == IPProto.IPv4
            else r"Mapped address: " + REG_IPV6ADDR + r".(\d+)"
        ),
        process.get_stdout(),
    )
    assert match, "stun response missing the IP address: " + process.get_stdout()

    return match.group((1 if ip_proto == IPProto.IPv4 else 0))
