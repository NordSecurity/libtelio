import asyncio
import itertools
import subprocess
import threading
import time
from contextlib import AsyncExitStack
from datetime import datetime
from tests.utils.connection import ConnectionTag
from tests.utils.connection.docker_connection import container_id
from tests.utils.connection_util import new_connection_raw, is_running
from tests.utils.logger import setup_log
from tests.utils.tcpdump import make_local_tcpdump, make_tcpdump
from typing import List


async def start_tcpdump_processes(
    exit_stack: AsyncExitStack,
):
    connections = []
    for gw_tag in ConnectionTag:
        if gw_tag is ConnectionTag.VM_OPENWRT_GW_1:
            continue
        if "_GW" in gw_tag.name:
            if not await is_running(gw_tag):
                continue
            connection = await exit_stack.enter_async_context(
                new_connection_raw(gw_tag)
            )
            connections.append(connection)
    for conn_tag in [
        ConnectionTag.DOCKER_DNS_SERVER_1,
        ConnectionTag.DOCKER_DNS_SERVER_2,
    ]:
        if await is_running(conn_tag):
            connection = await exit_stack.enter_async_context(
                new_connection_raw(conn_tag)
            )
            connections.append(connection)

    await exit_stack.enter_async_context(make_tcpdump(connections, session=True))
    await exit_stack.enter_async_context(make_local_tcpdump())


async def start_windows_vms_resource_monitoring(
    tasks: List[asyncio.Task],
    end_tasks: threading.Event,
):
    vms = [ConnectionTag.DOCKER_WINDOWS_VM_1, ConnectionTag.DOCKER_WINDOWS_VM_2]
    for vm_tag in vms:
        is_vm_running = await is_running(vm_tag)
        if is_vm_running:
            funcs = [
                start_windows_vm_cpu_monitoring(vm_tag),
                start_windows_vm_memory_monitoring(vm_tag),
                start_windows_vm_top10_cpu_usage_monitoring(vm_tag),
                start_windows_vm_top10_memory_usage_monitoring(vm_tag),
            ]
            run_windows_vm_monitoring_funcs(funcs, tasks, end_tasks)


def run_windows_vm_monitoring_funcs(
    funcs,
    tasks: List[asyncio.Task],
    end_tasks: threading.Event,
):
    def aux():
        while not end_tasks.is_set():
            for func in funcs:
                func()

    tasks += [
        asyncio.create_task(asyncio.to_thread(aux))
    ]  # Storing the task to keep it alive


def start_windows_vm_top10_cpu_usage_monitoring(vm_tag):
    powershell_cmd = r"""
    Get-Counter '\Process(*)\% Processor Time' -ErrorAction SilentlyContinue |
    Select-Object -ExpandProperty CounterSamples |
    Where-Object {$_.InstanceName -ne '_total' -and $_.InstanceName -ne 'idle'} |
    Sort-Object CookedValue -Descending |
    Select-Object -First 10 InstanceName, @{Name='CPU%';Expression={[math]::Round($_.CookedValue,2)}}
    """
    return start_windows_vm_top10_usage_monitoring(vm_tag, "cpu", powershell_cmd)


def start_windows_vm_top10_memory_usage_monitoring(vm_tag):
    powershell_cmd = (
        "ps | sort ws -desc | select -first 10 name,@{n='MB';e={[int]($_.ws/1mb)}}"
    )
    return start_windows_vm_top10_usage_monitoring(vm_tag, "memory", powershell_cmd)


def start_windows_vm_top10_usage_monitoring(
    vm_tag: ConnectionTag, resource_name: str, powershell_cmd: str
):
    def aux():
        output_filename = f"logs/top10_{resource_name}_usage_{vm_tag}.txt"
        first = True
        with open(output_filename, "a", encoding="utf-8") as output_file:
            # This command takes usually ~5s to complete, so I've decided not to add any
            # additional explicit sleep

            result = subprocess.run(
                [
                    "docker",
                    "exec",
                    container_id(vm_tag),
                    "python3",
                    "/run/qga.py",
                    "--powershell",
                    powershell_cmd,
                ],
                capture_output=True,
                text=True,
            )
            if result.returncode != 0:
                setup_log.warning(
                    "powershell command for top10 %s failed on %s: %s",
                    resource_name,
                    vm_tag,
                    result.stderr,
                )
                time.sleep(1)
                return
            lines = result.stdout.splitlines()
            lines = list(itertools.dropwhile(lambda x: "STDOUT:" not in x, lines))[1:]
            lines = [x.strip() for x in lines if x != ""]
            current_time_iso = datetime.now().isoformat()
            top10 = "\n".join(lines)
            if first:
                first = False
            else:
                output_file.write("\n")
            output_file.write(f"{current_time_iso}{top10}\n")

    return aux


def start_windows_vm_monitoring(
    vm_tag: ConnectionTag, resource_name: str, powershell_cmd: str
):
    def aux():
        output_filename = f"logs/{resource_name}_usage_{vm_tag}.csv"
        with open(output_filename, "a", encoding="utf-8") as output_file:
            # This command takes usually ~5s to complete, so I've decided not to add any
            # additional explicit sleep
            result = subprocess.run(
                [
                    "docker",
                    "exec",
                    container_id(vm_tag),
                    "python3",
                    "/run/qga.py",
                    "--powershell",
                    powershell_cmd,
                ],
                capture_output=True,
                text=True,
            )
            if result.returncode != 0:
                setup_log.warning(
                    "powershell command for %s failed on %s: %s",
                    resource_name,
                    vm_tag,
                    result.stderr,
                )
                time.sleep(1)
                return
            lines = result.stdout.splitlines()
            lines = list(itertools.dropwhile(lambda x: "STDOUT:" not in x, lines))[1:]
            lines = [x.strip() for x in lines if x != ""]
            current_time_iso = datetime.now().isoformat()
            output_file.write(f"{current_time_iso}, {', '.join(lines)}\n")

    return aux


def start_windows_vm_memory_monitoring(vm_tag: ConnectionTag):
    cmd = """
    $os = Get-CimInstance Win32_OperatingSystem
    $totalRAM = [math]::Round($os.TotalVisibleMemorySize/1MB, 2)
    $freeRAM = [math]::Round($os.FreePhysicalMemory/1MB, 2)
    $usedRAM = $totalRAM - $freeRAM
    $percentUsed = [math]::Round(($usedRAM/$totalRAM)*100, 2)

    Write-Host "$totalRAM, $usedRAM, $freeRAM, $percentUsed"
    """
    return start_windows_vm_monitoring(vm_tag, "memory", cmd)


def start_windows_vm_cpu_monitoring(vm_tag: ConnectionTag):
    cmd = "(Get-Counter '\\Processor(*)\\% Processor Time').CounterSamples.CookedValue"
    return start_windows_vm_monitoring(vm_tag, "cpu", cmd)
