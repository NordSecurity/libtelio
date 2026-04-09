import os
import shutil
import subprocess
from tests.config import LAN_ADDR_MAP
from tests.utils.connection import ConnectionTag
from tests.utils.connection.ssh_connection import SshConnection
from tests.utils.connection_util import new_connection_raw
from tests.utils.logger import log, setup_log
from tests.utils.process import ProcessExecError

LOG_DIR = "logs"


def save_dmesg_from_host(suffix):
    try:
        result = subprocess.run(
            ["sudo", "dmesg", "-d", "-T"],
            capture_output=True,
            text=True,
            check=True,
        ).stdout
    except subprocess.CalledProcessError as e:
        setup_log.error("Error executing dmesg: %s", e)
        return

    if result:
        with open(
            os.path.join(LOG_DIR, f"dmesg-{suffix}.txt"), "w", encoding="utf-8"
        ) as f:
            f.write(result)


async def save_dmesg_from_remote_vm(conn_tag: ConnectionTag, suffix: str) -> None:
    os.makedirs(LOG_DIR, exist_ok=True)

    file_suffix = f"{conn_tag.name.lower()}-{suffix}"
    log_path = os.path.join(LOG_DIR, f"dmesg-{file_suffix}.txt")

    async with new_connection_raw(conn_tag) as conn:
        dmesg_cmd = ["dmesg", "-d", "-T"]
        try:
            proc = await conn.create_process(dmesg_cmd, quiet=True).execute()
            stdout = proc.get_stdout() or ""
            with open(log_path, "w", encoding="utf-8") as f:
                f.write(stdout)
        except ProcessExecError as e:
            setup_log.warning(
                "Failed to collect remote dmesg from %s. Return code=%s, stderr=%r, stdout=%r",
                conn_tag,
                e.returncode,
                e.stderr,
                e.stdout,
            )


def save_audit_log_from_host(suffix):
    try:
        source_path = "/var/log/audit/audit.log"
        if os.path.exists(source_path):
            shutil.copy2(source_path, f"{LOG_DIR}/audit_{suffix}.log")
        else:
            setup_log.warning("The audit file %s", source_path)
    except Exception as e:  # pylint: disable=broad-exception-caught
        setup_log.warning("An error occurred when processing audit log: %s", e)


async def save_nordlynx_logs(session_vm_marks: set[str]):
    if "nlx" not in session_vm_marks:
        return

    source_log_dir_path = "/var/log"
    nlx_log_files = [
        "nlx-radius.log",
        "pq-upgrader.log",
        "fakefm.log",
        "nlx-ns.log",
        "dynamic_api_fakefm.log",
    ]

    async with new_connection_raw(ConnectionTag.VM_LINUX_NLX_1) as conn:
        for log_file in nlx_log_files:
            remote_path = os.path.join(source_log_dir_path, log_file)
            local_path = os.path.join(LOG_DIR, log_file)
            try:
                await conn.download(remote_path, local_path)
                log.info("Downloaded '%s' to '%s'", remote_path, local_path)
            except Exception as e:  # pylint: disable=broad-exception-caught
                setup_log.warning(
                    "An error occurred when processing %s log: %s", remote_path, e
                )


async def _save_macos_logs(conn, suffix):
    try:
        dmesg_proc = await conn.create_process(["dmesg"], quiet=True).execute()
        with open(
            os.path.join(LOG_DIR, f"dmesg-macos-{suffix}.txt"), "w", encoding="utf-8"
        ) as f:
            f.write(dmesg_proc.get_stdout())
    except ProcessExecError as e:
        setup_log.warning("Failed to collect dmesg logs %s", e)


async def collect_kernel_logs(
    suffix,
    session_vm_marks: set[str],
):
    os.makedirs(LOG_DIR, exist_ok=True)

    save_dmesg_from_host(suffix)
    save_audit_log_from_host(suffix)
    await save_dmesg_from_remote_vm(ConnectionTag.VM_LINUX_NLX_1, suffix)

    if "mac" in session_vm_marks:
        try:
            async with SshConnection.new_connection(
                LAN_ADDR_MAP[ConnectionTag.VM_MAC]["primary"], ConnectionTag.VM_MAC
            ) as conn:
                await _save_macos_logs(conn, suffix)
        except OSError as e:
            if os.environ.get("GITLAB_CI"):
                raise e


async def collect_logs(
    session_vm_marks: set[str],
):
    collect_nordderper_logs()
    collect_dns_server_logs()
    collect_core_api_server_logs()
    await collect_kernel_logs("after_tests", session_vm_marks)
    await collect_mac_diagnostic_reports(session_vm_marks)
    await save_nordlynx_logs(session_vm_marks)


def collect_nordderper_logs():
    num_containers = 3

    for i in range(1, num_containers + 1):
        container_name = f"nat-lab-derp-{i:02d}-1"
        destination_path = f"{LOG_DIR}/derp_{i:02d}_relay.log"

        copy_file_from_container(
            container_name, "/etc/nordderper/relay.log", destination_path
        )


def collect_dns_server_logs():
    num_containers = 2

    for i in range(1, num_containers + 1):
        container_name = f"nat-lab-dns-server-{i}-1"
        destination_path = f"{LOG_DIR}/dns_server_{i}.log"

        copy_file_from_container(container_name, "/dns-server.log", destination_path)


def collect_core_api_server_logs():
    container_name = "nat-lab-core-api-1"
    os.makedirs(LOG_DIR, exist_ok=True)
    out_path = os.path.join(LOG_DIR, "core_api.log")
    with open(out_path, "w", encoding="utf-8") as f:
        subprocess.run(
            ["docker", "logs", container_name],
            stdout=f,
            stderr=subprocess.STDOUT,
            text=True,
            check=True,
        )


def copy_file_from_container(container_name, src_path, dst_path):
    docker_cp_command = f"docker cp {container_name}:{src_path} {dst_path}"
    try:
        subprocess.run(docker_cp_command, shell=True, check=True)
        setup_log.info(
            "Log file %s copied successfully from %s to %s",
            src_path,
            container_name,
            dst_path,
        )
    except subprocess.CalledProcessError:
        setup_log.warning(
            "Error copying log file %s from %s to %s",
            src_path,
            container_name,
            dst_path,
        )


async def collect_mac_diagnostic_reports(
    session_vm_marks: set[str],
):
    is_ci = "GITLAB_CI" in os.environ
    if not (
        is_ci
        or "NATLAB_COLLECT_MAC_DIAGNOSTIC_LOGS" in os.environ
        or "mac" in session_vm_marks
    ):
        return
    setup_log.info("Collect mac diagnostic reports")
    async with SshConnection.new_connection(
        LAN_ADDR_MAP[ConnectionTag.VM_MAC]["primary"], ConnectionTag.VM_MAC
    ) as connection:
        await connection.download(
            "/Library/Logs/DiagnosticReports",
            f"{LOG_DIR}/system_diagnostic_reports",
        )
        await connection.download(
            "/root/Library/Logs/DiagnosticReports",
            f"{LOG_DIR}/user_diagnostic_reports",
        )
