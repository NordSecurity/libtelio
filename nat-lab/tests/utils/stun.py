import re
from config import STUN_BINARY_PATH_WINDOWS, STUN_BINARY_PATH_MAC
from utils.connection import Connection, TargetOS

# For Linux, use the standard `stunclient` available on most distributions.
#
# For Windows, stun binaries are available from
# http://www.stunprotocol.org/
#
# For Mac, stun binaries are available from
# https://master.dl.sourceforge.net/project/stuntman/stunserver_osx_1_2_13.zip?viasf=1


async def get(
    connection: Connection, stun_server: str, stun_server_port: int = 3478
) -> str:
    if connection.target_os == TargetOS.Linux:
        process = await connection.create_process(
            ["turnutils_stunclient", "-p", str(stun_server_port), stun_server]
        ).execute()

        match = re.search(
            r"UDP reflexive addr: (\d+\.\d+\.\d+\.\d+):(\d+)", process.get_stdout()
        )
        assert match, (
            f"stun response missing XorMappedAddress, stdout {process.get_stdout()},"
            f" stderr {process.get_stderr()}"
        )
        return match.group(1)

    if connection.target_os == TargetOS.Windows:
        assert (
            stun_server_port == 3478
        ), "Non-standard Stun ports are supported only on Linux"

        process = await connection.create_process(
            [STUN_BINARY_PATH_WINDOWS, stun_server]
        ).execute()

        # Match: 'Mapped address: 10.0.0.1:53628'
        match = re.search(r"Mapped address: (\d+.\d+.\d+.\d+)", process.get_stdout())
        assert match, (
            f"stun response missing Mapped address, stdout {process.get_stdout()},"
            f" stderr {process.get_stderr()}"
        )
        return match.group(1)

    if connection.target_os == TargetOS.Mac:
        assert (
            stun_server_port == 3478
        ), "Non-standard Stun ports are supported only on Linux"

        process = await connection.create_process(
            [STUN_BINARY_PATH_MAC, stun_server]
        ).execute()

        # Match: 'Mapped address: 10.0.0.1:53628'
        match = re.search(r"Mapped address: (\d+.\d+.\d+.\d+)", process.get_stdout())
        assert match, (
            f"stun response missing Mapped address, stdout {process.get_stdout()},"
            f" stderr {process.get_stderr()}"
        )
        return match.group(1)

    assert False, "unsupported os"
