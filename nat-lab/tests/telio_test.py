from utils.asyncio_util import run_async
from telio import State, Runtime, Events
from typing import List
import asyncio
import pytest
import utils.testing as testing


class TestRuntime:
    @pytest.mark.asyncio
    async def test_wait_output(self) -> None:
        runtime = Runtime()

        async def wait_output(what) -> None:
            event = asyncio.Event()
            runtime.get_output_notifier().notify_output(what, event)
            await testing.wait_short(event.wait())

        futures: List[asyncio.Future] = []
        futures.append(run_async(wait_output("started telio")))
        futures.append(run_async(wait_output("started")))
        futures.append(run_async(wait_output("natlab injected")))

        await asyncio.sleep(0.01)

        assert runtime.handle_output_line("- started telio...")
        assert not runtime.handle_output_line("- started telio...")

        assert runtime.handle_output_line("natlab injected")
        assert not runtime.handle_output_line("natlab injected")

        for future in futures:
            await testing.wait_short(future)

    @pytest.mark.asyncio
    async def test_set_peer_state(self) -> None:
        runtime = Runtime()

        event = asyncio.Event()
        runtime.notify_peer_state("AAA", event)
        runtime.allowed_pub_keys = set(["AAA"])

        runtime._set_peer_state("AAA", State.Connected, "")
        await testing.wait_short(event.wait())

        peer_info = runtime.get_peer_info("AAA")
        assert peer_info is not None and peer_info.state == State.Connected

    @pytest.mark.asyncio
    async def test_handle_node_event(self) -> None:
        runtime = Runtime()
        runtime.allowed_pub_keys = set(["AAA"])
        assert runtime.handle_output_line(
            'event node: "{"identifier":"tcli","public_key":"AAA","state":"connected","is_exit":true,"is_vpn":true,"allowed_ips":[],"endpoint":null,"hostname":null,"allow_incoming_connections":false,"allow_peer_send_files":false,"path":"relay"}"'
        )
        peer_info = runtime.get_peer_info("AAA")
        assert peer_info is not None and peer_info.state == State.Connected


class TestEvents:
    @pytest.mark.asyncio
    async def test_handshake(self) -> None:
        runtime = Runtime()
        events = Events(runtime)

        join_handshake = run_async(events.wait_for_state("BBB", State.Connected))
        await asyncio.sleep(1)  # Wait for handshake coroutine to start
        runtime.allowed_pub_keys = set(["AAA", "BBB"])
        runtime._set_peer_state("AAA", State.Connected)
        runtime._set_peer_state("BBB", State.Connected)

        await testing.wait_short(join_handshake)

        # Handshake already achieved, should return immediately
        await testing.wait_short(events.wait_for_state("BBB", State.Connected))
