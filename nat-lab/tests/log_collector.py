import glob
import os
import warnings
from tests.utils.connection import Connection, ConnectionTag, TargetOS
from tests.utils.connection.docker_connection import DockerConnection, container_id
from tests.utils.logger import log
from tests.utils.moose import MOOSE_LOGS_DIR
from tests.utils.process import ProcessExecError
from tests.utils.router import Router
from tests.utils.testing import (
    get_current_test_case_and_parameters,
    get_current_test_log_path,
)
from typing import List, Optional, Pattern


async def find_files(
    connection: Connection, where: str, name_pattern: str
) -> List[str]:
    """Wrapper for 'find' command over the connection"""

    try:
        process = await connection.create_process(
            ["find", where, "-maxdepth", "1", "-name", name_pattern], quiet=True
        ).execute()
        return process.get_stdout().strip().split()
    except ProcessExecError:
        # Expected when 'where' doesn't exist
        return []


async def copy_file(
    from_connection: Connection, from_path: str, destination_path: str
) -> None:
    """Copy a file from within the docker container connection to the destination path"""
    if isinstance(from_connection, DockerConnection):
        file_name = os.path.basename(from_path)
        core_dump_destination = os.path.join(destination_path, file_name)

        await from_connection.download(from_path, core_dump_destination)
    else:
        raise Exception(f"Copying files from {from_connection} is not supported")


async def get_log_without_flush(connection: Connection) -> str:
    """
    This function retrieves telio logs without flushing them. It may be needed to do that
    if log retrieval is requested after process has already exited. In such a case there is
    nothing to flush and attempting to do so will cause errors.
    """
    process = (
        connection.create_process(["type", "tcli.log"], quiet=True)
        if connection.target_os == TargetOS.Windows
        else connection.create_process(["cat", "./tcli.log"], quiet=True)
    )
    await process.execute()
    return process.get_stdout()


async def get_network_info(connection: Connection, start_time) -> str:
    if connection.target_os == TargetOS.Mac:
        interface_info = connection.create_process(["ifconfig", "-a"], quiet=True)
        await interface_info.execute()
        routing_table_info = connection.create_process(["netstat", "-rn"], quiet=True)
        await routing_table_info.execute()
        # syslog does not provide a way to filter events by timestamp, so only using the last 20 lines.
        syslog_info = connection.create_process(["syslog"], quiet=True)
        await syslog_info.execute()
        start_time_str = start_time.strftime("%Y-%m-%d %H:%M:%S")
        log_info = connection.create_process(
            ["log", "show", "--start", start_time_str], quiet=True
        )
        await log_info.execute()
        return (
            start_time_str
            + "\n"
            + "\n"
            + routing_table_info.get_stdout()
            + "\n"
            + interface_info.get_stdout()
            + "\n"
            + "\n".join(syslog_info.get_stdout().splitlines()[-20:])
            + "\n"
            + "\n"
            + log_info.get_stdout()
            + "\n"
            + "\n"
        )
    return ""


async def save_mac_network_info(connection: Connection, start_time) -> None:
    if os.environ.get("NATLAB_SAVE_LOGS") is None:
        return

    if connection.target_os != TargetOS.Mac:
        return

    log_dir = get_current_test_log_path()
    os.makedirs(log_dir, exist_ok=True)

    network_info_info = await get_network_info(connection, start_time)

    filename = connection.tag.name.lower() + "_network_info.log"
    if len(filename.encode("utf-8")) > 256:
        filename = f"{filename[:251]}.log"

        i = 0
        while os.path.exists(os.path.join(log_dir, filename)):
            filename = f"{filename[:249]}_{i}.log"
            i += 1

    with open(
        os.path.join(log_dir, filename),
        "w",
        encoding="utf-8",
    ) as f:
        f.write(network_info_info)


async def get_system_log(connection: Connection) -> Optional[str]:
    """
    Get the system log on the target machine
    Windows only for now
    """
    if connection.target_os == TargetOS.Windows:
        logs = ""
        for log_name in ["Application", "System"]:
            try:
                log_output = await connection.create_process(
                    [
                        "powershell",
                        "-Command",
                        (
                            f"Get-EventLog -LogName {log_name} -Newest 100 |"
                            " format-table -wrap"
                        ),
                    ],
                    quiet=True,
                ).execute()
                logs += log_output.get_stdout()
            except ProcessExecError:
                # ignore exec error, since it happens if no events were found
                pass
        return logs
    return None


async def save_logs(connection: Connection) -> None:
    """
    Save the logs from libtelio.
    In order to collect all of the logs this function must be called
    after process running libtelio has already exited. Or in worst case
    at least after logs has been flushed.
    """

    if os.environ.get("NATLAB_SAVE_LOGS") is None:
        return

    log_dir = get_current_test_log_path()
    os.makedirs(log_dir, exist_ok=True)

    try:
        log_content = await get_log_without_flush(connection)
    except ProcessExecError as err:
        err.print()
        return

    system_log_content = await get_system_log(connection)

    filename = connection.tag.name.lower() + ".log"
    if len(filename.encode("utf-8")) > 256:
        filename = f"{filename[:251]}.log"

        i = 0
        while os.path.exists(os.path.join(log_dir, filename)):
            filename = f"{filename[:249]}_{i}.log"
            i += 1

    with open(
        os.path.join(log_dir, filename),
        "w",
        encoding="utf-8",
    ) as f:
        f.write(log_content)
        if system_log_content:
            f.write("\n\n\n\n--- SYSTEM LOG ---\n\n")
            f.write(system_log_content)

    moose_traces = await find_files(connection, MOOSE_LOGS_DIR, "moose_trace.log*")
    for trace_path in moose_traces:
        await copy_file(connection, trace_path, log_dir)
        file_name = os.path.basename(trace_path)
        os.rename(
            os.path.join(log_dir, file_name),
            os.path.join(log_dir, f"{connection.tag.name.lower()}-{file_name}"),
        )

    if connection.target_os == TargetOS.Windows:
        await connection.download("C:\\Windows\\INF\\setupapi.dev.log", log_dir)
        await connection.download("C:\\Windows\\INF\\setupapi.setup.log", log_dir)


async def save_moose_db() -> None:
    """
    Check if any the moose db files exists ("*-events.db"),
    rename them to "str(test_name) + "_" + original_filename, and save them to "./logs",
    delete the original file.
    """
    if os.environ.get("NATLAB_SAVE_LOGS") is None:
        return

    log_dir = get_current_test_log_path()
    os.makedirs(log_dir, exist_ok=True)

    moose_db_files = glob.glob("*-events.db", recursive=False)

    for original_filename in moose_db_files:
        new_filepath = os.path.join(log_dir, original_filename)
        os.rename(original_filename, new_filepath)


# This is where natlab expects coredumps to be placed
# For CI and our internal linux VM, this path is set in our provisioning scripts
# If you're running locally without the aforementioned linux VM, you are expected to configure this yourself
# However, this only needs to be set iff you're:
#  - running a test targeting a docker image
#  - have set the NATLAB_SAVE_LOGS environment variable
#  - want to have natlab automatically collect core dumps for you
def get_coredump_folder() -> tuple[str, str]:
    return "/var/crash", "core-"


def should_skip_core_dump_collection(connection: Connection) -> bool:
    return (
        os.environ.get("NATLAB_SAVE_LOGS") is None
        or connection.target_os != TargetOS.Linux
    )


async def clear_core_dumps(connection: Connection) -> None:
    if should_skip_core_dump_collection(connection):
        return

    coredump_folder, _ = get_coredump_folder()

    # clear the existing system core dumps
    await connection.create_process(
        ["rm", "-rf", coredump_folder], quiet=True
    ).execute()
    # make sure we have the path where the new cores will be dumped
    await connection.create_process(
        ["mkdir", "-p", coredump_folder], quiet=True
    ).execute()


async def collect_core_dumps(connection: Connection) -> None:
    if should_skip_core_dump_collection(connection):
        return

    coredump_folder, file_prefix = get_coredump_folder()

    dump_files = await find_files(connection, coredump_folder, f"{file_prefix}*")

    coredump_dir = "coredumps"
    os.makedirs(coredump_dir, exist_ok=True)

    should_copy_coredumps = len(dump_files) > 0

    # if we collected some core dumps, copy them
    if isinstance(connection, DockerConnection) and should_copy_coredumps:
        container_name = container_id(connection.tag)
        test_name = get_current_test_case_and_parameters()[0] or ""
        for i, file_path in enumerate(dump_files):
            file_name = file_path.rsplit("/", 1)[-1]
            core_dump_destination = f"{coredump_dir}/{test_name}_{file_name}_{i}.core"
            cmd = (
                "docker container cp"
                f" {container_name}:{file_path} {core_dump_destination}"
            )
            os.system(cmd)


class LogCollector:
    tag: ConnectionTag
    node_name: str
    start_time: object
    router: Router
    allowed_errors: Optional[List[Pattern[str]]]

    def __init__(self, client):
        log.info(
            'os.environ.get("NATLAB_SAVE_LOGS"): %s', os.environ.get("NATLAB_SAVE_LOGS")
        )
        self.tag = client._connection.tag
        self.node_name = client._node.name
        self.start_time = client._start_time
        self.router = client._router
        self.allowed_errors = client._allowed_errors

    async def cleanup(self, connection: Connection) -> None:
        log.info(
            "[%s] Collecting core dumps",
            self.node_name,
        )
        await collect_core_dumps(connection)

        log.info(
            "[%s] Saving MacOS network info",
            self.node_name,
        )
        await save_mac_network_info(connection, self.start_time)

        log.info("[%s] Saving moose dbs", self.node_name)
        await save_moose_db()

        log.info("[%s] Checking logs", self.node_name)
        await self._check_logs_for_errors(connection)

        log.info("[%s] Saving logs", self.node_name)
        await save_logs(connection)

    async def _check_logs_for_errors(self, connection: Connection) -> None:
        """
        Check logs for error and raise error/warning if unexpected errors
        has been found

        In order to check all of the logs this function must be called
        after process running libtelio has already exited. Or in worst case
        at least after logs has been flushed.
        """

        log_content = await get_log_without_flush(connection)
        for line in log_content.splitlines():
            if "TelioLogLevel.ERROR" in line:
                if not self.allowed_errors or not any(
                    allowed.search(line) for allowed in self.allowed_errors
                ):
                    # TODO: convert back to `raise Exception()` once we are ready to investigate
                    warnings.warn(
                        f"Unexpected error found in {self.node_name} log: {line}"
                    )


LOG_COLLECTORS: List[LogCollector] = []
