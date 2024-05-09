import asyncio
import platform
from utils.connection_util import (
    ConnectionTag,
    get_libtelio_binary_path,
    new_connection_raw,
)
from utils.output_notifier import OutputNotifier

if platform.machine() != "x86_64":
    import pure_wg as Key
else:
    from python_wireguard import Key  # type: ignore


async def test_wg_adapter_cleanup():
    output_notifier = OutputNotifier()

    async def output_checker(stdout: str) -> None:
        for line in stdout.splitlines():
            print(line)
            output_notifier.handle_output(line)

    private, _ = Key.key_pair()

    async with new_connection_raw(ConnectionTag.WINDOWS_VM_1) as conn:
        cli_started = asyncio.Event()
        output_notifier.notify_output("telio dev cli", cli_started)

        adapter_started = asyncio.Event()
        output_notifier.notify_output("started telio with", adapter_started)

        async with conn.create_process([get_libtelio_binary_path("tcli", conn)]).run(
            output_checker, output_checker
        ) as tcli_proc:
            await tcli_proc.wait_stdin_ready()
            await cli_started.wait()
            await tcli_proc.write_stdin(
                f"dev start wireguard-go wintun10 {str(private)}\n"
            )
            await adapter_started.wait()

        # leaving previous stack here in theory should kill tcli in a dirty manner,
        # leaving orphaned wintun adapter behind, but doesn't happen 100% tho

        reg_query = await conn.create_process([
            "reg",
            "query",
            r"HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}",
            "/s",
            "/f",
            "DeviceInstanceID",
        ]).execute()

        while (
            "tcli.exe"
            in (await conn.create_process(["tasklist"]).execute()).get_stdout()
        ):
            await asyncio.sleep(0.1)

        # as mentioned before, wintun adapter is not left behind 100%
        # if it is not there, we do nothing
        if "Wintun" not in reg_query.get_stdout():
            return

        cli_started = asyncio.Event()
        output_notifier.notify_output("telio dev cli", cli_started)

        adapter_started = asyncio.Event()
        output_notifier.notify_output("started telio with", adapter_started)

        telio_stoppped = asyncio.Event()
        output_notifier.notify_output("- stopped telio.", telio_stoppped)

        async with conn.create_process([get_libtelio_binary_path("tcli", conn)]).run(
            output_checker, output_checker
        ) as tcli_proc:
            await tcli_proc.wait_stdin_ready()
            await cli_started.wait()
            await tcli_proc.write_stdin(
                f"dev start wireguard-go wintun10 {str(private)}\n"
            )
            await adapter_started.wait()
            await tcli_proc.write_stdin("dev stop\n")
            await telio_stoppped.wait()
            await tcli_proc.write_stdin("quit\n")
