import asyncio
import copy
import pytest
import time
from tests.telio import Runtime, Events, WontHappenError
from tests.utils.asyncio_util import run_async_contexts, run_async_context
from tests.utils.bindings import (
    NodeState,
    RelayState,
    PathType,
    Server,
    telio_node,
    Event,
)
from tests.utils.testing import log_test_passed


def create_derpserver_config(state: RelayState) -> Server:
    return Server(
        region_code="test",
        name="test",
        hostname="test-01",
        ipv4="1.1.1.1",
        relay_port=1111,
        stun_port=1111,
        stun_plaintext_port=1111,
        public_key="test",
        weight=1,
        use_plain_text=True,
        conn_state=state,
    )


class TestRuntime:
    @pytest.mark.asyncio
    async def test_wait_output(self) -> None:
        runtime = Runtime()

        async def wait_output(what: str) -> None:
            event = asyncio.Event()
            runtime.get_output_notifier().notify_output(what, event)
            await event.wait()

        async with run_async_contexts([
            wait_output("started telio"),
            wait_output("started"),
            wait_output("natlab injected"),
        ]) as future_list:
            await asyncio.sleep(0)

            assert await runtime.handle_output_line("- started telio...")
            assert not await runtime.handle_output_line("- started telio...")

            assert await runtime.handle_output_line("natlab injected")
            assert not await runtime.handle_output_line("natlab injected")

            for future in future_list:
                await future

        log_test_passed()

    @pytest.mark.asyncio
    async def test_set_peer_state(self) -> None:
        runtime = Runtime()
        runtime.allowed_pub_keys = set(["AAA", "BBB"])

        runtime.set_peer(
            telio_node(
                public_key="AAA", state=NodeState.CONNECTED, path=PathType.RELAY
            ),
            42.0,
        )

        runtime.set_peer(
            telio_node(
                public_key="BBB", state=NodeState.DISCONNECTED, path=PathType.DIRECT
            ),
            43.0,
        )

        await runtime.notify_peer_state("AAA", [NodeState.CONNECTED], [PathType.RELAY])
        await runtime.notify_peer_state(
            "BBB", [NodeState.DISCONNECTED], [PathType.DIRECT]
        )

        # it should pass again
        await runtime.notify_peer_state(
            "AAA", [NodeState.CONNECTED], [PathType.RELAY, PathType.DIRECT]
        )

        # it should fail (wrong state)
        with pytest.raises(asyncio.TimeoutError):
            await asyncio.wait_for(
                runtime.notify_peer_state(
                    "BBB", [NodeState.CONNECTED], [PathType.DIRECT]
                ),
                0.1,
            )

        # it should fail (wrong path)
        with pytest.raises(asyncio.TimeoutError):
            await asyncio.wait_for(
                runtime.notify_peer_state(
                    "AAA", [NodeState.CONNECTED], [PathType.DIRECT]
                ),
                0.1,
            )

        log_test_passed()

    @pytest.mark.asyncio
    async def test_set_peer_event(self) -> None:
        runtime = Runtime()
        runtime.allowed_pub_keys = set(["AAA"])

        # Start waiting for new event before it is being generated
        async with run_async_context(
            runtime.notify_peer_event("AAA", [NodeState.CONNECTED], [PathType.RELAY])
        ) as future:
            # wait for futures to be started
            await asyncio.sleep(0)
            runtime.set_peer(
                telio_node(public_key="AAA", state=NodeState.CONNECTED), 42.0
            )
            await future

        with pytest.raises(asyncio.TimeoutError):
            await asyncio.wait_for(
                runtime.notify_peer_event(
                    "AAA", [NodeState.CONNECTED], [PathType.RELAY]
                ),
                0.1,
            )

        log_test_passed()

    @pytest.mark.asyncio
    async def test_notify_peer_event_in_duration(self) -> None:
        runtime = Runtime()
        runtime.allowed_pub_keys = set(["AAA"])

        with pytest.raises(WontHappenError):
            now = time.time()
            runtime.set_peer(
                telio_node(
                    public_key="AAA", state=NodeState.CONNECTED, path=PathType.RELAY
                ),
                timestamp=now + 10.0,
            )
            await runtime.notify_peer_event_in_duration(
                "AAA", [NodeState.CONNECTED], 5, [PathType.RELAY]
            )

        log_test_passed()

    @pytest.mark.asyncio
    async def test_set_derp_state(self) -> None:
        runtime = Runtime()
        runtime.set_derp(create_derpserver_config(RelayState.CONNECTED))
        await runtime.notify_derp_state("1.1.1.1", [RelayState.CONNECTED])

        # it should pass again
        await runtime.notify_derp_state(
            "1.1.1.1",
            [RelayState.DISCONNECTED, RelayState.CONNECTING, RelayState.CONNECTED],
        )

        # it should fail (wrong state)
        with pytest.raises(asyncio.TimeoutError):
            await asyncio.wait_for(
                runtime.notify_derp_state("1.1.1.1", [RelayState.DISCONNECTED]), 0.1
            )

        # it should fail (wrong IP)
        with pytest.raises(asyncio.TimeoutError):
            await asyncio.wait_for(
                runtime.notify_derp_state("1.1.1.2", [RelayState.CONNECTED]), 0.1
            )

        log_test_passed()

    @pytest.mark.asyncio
    async def test_set_derp_event(self) -> None:
        runtime = Runtime()

        async with run_async_context(
            runtime.notify_derp_event("1.1.1.1", [RelayState.CONNECTED])
        ) as future:
            # wait for futures to be started
            await asyncio.sleep(0)
            runtime.set_derp(create_derpserver_config(RelayState.CONNECTED))
            await future

        with pytest.raises(asyncio.TimeoutError):
            await asyncio.wait_for(
                runtime.notify_derp_event("1.1.1.1", [RelayState.CONNECTED]), 0.1
            )

        log_test_passed()

    @pytest.mark.asyncio
    async def test_handle_derp_event(self) -> None:
        runtime = Runtime()

        server = Server(
            region_code="test",
            name="test",
            hostname="test",
            ipv4="1.1.1.1",
            relay_port=1111,
            stun_port=1111,
            stun_plaintext_port=1111,
            public_key="test",
            weight=1,
            use_plain_text=True,
            conn_state=RelayState.CONNECTED,
        )
        event = Event.RELAY(server)
        runtime.handle_event(event, 42.0)  # type: ignore

        await runtime.notify_derp_state("1.1.1.1", [RelayState.CONNECTED])

        log_test_passed()

    @pytest.mark.asyncio
    async def test_handle_node_event(self) -> None:
        runtime = Runtime()
        runtime.allowed_pub_keys = set(["AAA"])

        node = telio_node(
            identifier="tcli",
            public_key="AAA",
            state=NodeState.CONNECTED,
            is_exit=True,
            is_vpn=True,
        )
        event = Event.NODE(node)
        runtime.handle_event(event, 42.0)  # type: ignore

        await runtime.notify_peer_state(
            "AAA", [NodeState.CONNECTED], [PathType.RELAY], is_exit=True, is_vpn=True
        )

        log_test_passed()


class TestEvents:
    @pytest.mark.asyncio
    async def test_peer_state(self) -> None:
        runtime = Runtime()
        events = Events(runtime)

        runtime.allowed_pub_keys = set(["AAA", "BBB"])

        runtime.set_peer(
            telio_node(
                public_key="AAA", state=NodeState.CONNECTED, path=PathType.RELAY
            ),
            42.0,
        )
        runtime.set_peer(
            telio_node(
                public_key="BBB", state=NodeState.DISCONNECTED, path=PathType.DIRECT
            ),
            43.0,
        )

        await events.wait_for_state_peer("AAA", [NodeState.CONNECTED], [PathType.RELAY])
        await events.wait_for_state_peer(
            "BBB", [NodeState.DISCONNECTED], [PathType.DIRECT]
        )

        # it should pass again
        await events.wait_for_state_peer(
            "AAA", [NodeState.CONNECTED], [PathType.RELAY, PathType.DIRECT]
        )
        await events.wait_for_state_peer(
            "BBB", [NodeState.DISCONNECTED], [PathType.RELAY, PathType.DIRECT]
        )

        # it should fail (wrong state)
        with pytest.raises(asyncio.TimeoutError):
            await events.wait_for_state_peer(
                "BBB", [NodeState.CONNECTED], [PathType.DIRECT], timeout=0.1
            )

        # it should fail (wrong path)
        with pytest.raises(asyncio.TimeoutError):
            await events.wait_for_state_peer(
                "AAA", [NodeState.CONNECTED], [PathType.DIRECT], timeout=0.1
            )

        log_test_passed()

    @pytest.mark.asyncio
    async def test_peer_change_state(self) -> None:
        runtime = Runtime()
        events = Events(runtime)
        runtime.allowed_pub_keys = set(["AAA", "BBB"])

        runtime.set_peer(telio_node(public_key="AAA", state=NodeState.CONNECTED), 42.0)
        runtime.set_peer(telio_node(public_key="BBB", state=NodeState.CONNECTED), 43.0)

        await events.wait_for_state_peer("BBB", [NodeState.CONNECTED], [PathType.RELAY])
        await events.wait_for_state_peer("AAA", [NodeState.CONNECTED], [PathType.RELAY])

        runtime.set_peer(
            telio_node(public_key="AAA", state=NodeState.DISCONNECTED), 44.0
        )
        runtime.set_peer(
            telio_node(public_key="BBB", state=NodeState.DISCONNECTED), 45.0
        )

        await events.wait_for_state_peer(
            "BBB", [NodeState.DISCONNECTED], [PathType.RELAY]
        )
        await events.wait_for_state_peer(
            "AAA", [NodeState.DISCONNECTED], [PathType.RELAY]
        )

        # It should pass again
        await events.wait_for_state_peer(
            "BBB", [NodeState.DISCONNECTED], [PathType.RELAY, PathType.DIRECT]
        )
        await events.wait_for_state_peer(
            "AAA", [NodeState.DISCONNECTED], [PathType.RELAY, PathType.DIRECT]
        )

        # it should fail (old state)
        with pytest.raises(asyncio.TimeoutError):
            await events.wait_for_state_peer(
                "BBB", [NodeState.CONNECTED], [PathType.RELAY], timeout=0.1
            )

        # it should fail (wrong path)
        with pytest.raises(asyncio.TimeoutError):
            await events.wait_for_state_peer(
                "AAA", [NodeState.DISCONNECTED], [PathType.DIRECT], timeout=0.1
            )

        log_test_passed()

    @pytest.mark.asyncio
    async def test_peer_event(self) -> None:
        runtime = Runtime()
        events = Events(runtime)
        runtime.allowed_pub_keys = set(["AAA", "BBB"])

        # Start waiting for new event before it is being generated
        async with run_async_context(
            events.wait_for_event_peer(
                "AAA", [NodeState.CONNECTED], [PathType.RELAY], timeout=1
            )
        ) as future:
            # wait for futures to be started
            await asyncio.sleep(0)

            runtime.set_peer(
                telio_node(public_key="BBB", state=NodeState.CONNECTED), 42.0
            )
            with pytest.raises(asyncio.TimeoutError):
                await asyncio.wait_for(asyncio.shield(future), 0.1)

            runtime.set_peer(
                telio_node(public_key="AAA", state=NodeState.DISCONNECTED), 43.0
            )
            with pytest.raises(asyncio.TimeoutError):
                await asyncio.wait_for(asyncio.shield(future), 0.1)

            runtime.set_peer(
                telio_node(public_key="AAA", state=NodeState.CONNECTING), 44.0
            )
            with pytest.raises(asyncio.TimeoutError):
                await asyncio.wait_for(asyncio.shield(future), 0.1)

            runtime.set_peer(
                telio_node(
                    public_key="AAA", state=NodeState.CONNECTED, path=PathType.DIRECT
                ),
                45.0,
            )
            with pytest.raises(asyncio.TimeoutError):
                await asyncio.wait_for(asyncio.shield(future), 0.1)

            runtime.set_peer(
                telio_node(public_key="AAA", state=NodeState.CONNECTED), 46.0
            )
            await future

        with pytest.raises(asyncio.TimeoutError):
            await events.wait_for_event_peer(
                "AAA", [NodeState.CONNECTED], [PathType.RELAY], timeout=0.1
            )

        log_test_passed()

    @pytest.mark.asyncio
    async def test_peer_with_multiple_events(self) -> None:
        runtime = Runtime()
        events = Events(runtime)
        runtime.allowed_pub_keys = set(["AAA", "BBB"])

        # Start waiting for new event before it is being generated
        async with run_async_contexts([
            events.wait_for_event_peer(
                "AAA", [NodeState.DISCONNECTED], [PathType.RELAY], timeout=5
            ),
            events.wait_for_event_peer(
                "AAA", [NodeState.CONNECTING], [PathType.RELAY], timeout=5
            ),
            events.wait_for_event_peer(
                "AAA", [NodeState.CONNECTED], [PathType.RELAY], timeout=5
            ),
            events.wait_for_event_peer(
                "BBB", [NodeState.DISCONNECTED], [PathType.DIRECT], timeout=5
            ),
            events.wait_for_event_peer(
                "BBB", [NodeState.CONNECTING], [PathType.DIRECT], timeout=5
            ),
            events.wait_for_event_peer(
                "BBB", [NodeState.CONNECTED], [PathType.DIRECT], timeout=5
            ),
        ]) as futures:
            # wait for futures to be started
            await asyncio.sleep(0)

            runtime.set_peer(
                telio_node(
                    public_key="BBB", state=NodeState.CONNECTED, path=PathType.RELAY
                ),
                42.0,
            )
            runtime.set_peer(
                telio_node(
                    public_key="AAA", state=NodeState.CONNECTED, path=PathType.DIRECT
                ),
                43.0,
            )
            for future in futures:
                with pytest.raises(asyncio.TimeoutError):
                    await asyncio.wait_for(asyncio.shield(future), 0.1)

            runtime.set_peer(
                telio_node(
                    public_key="AAA", state=NodeState.DISCONNECTED, path=PathType.RELAY
                ),
                44.0,
            )
            runtime.set_peer(
                telio_node(
                    public_key="AAA", state=NodeState.CONNECTING, path=PathType.RELAY
                ),
                45.0,
            )
            runtime.set_peer(
                telio_node(
                    public_key="AAA", state=NodeState.CONNECTED, path=PathType.RELAY
                ),
                46.0,
            )
            runtime.set_peer(
                telio_node(
                    public_key="BBB", state=NodeState.DISCONNECTED, path=PathType.DIRECT
                ),
                47.0,
            )
            runtime.set_peer(
                telio_node(
                    public_key="BBB", state=NodeState.CONNECTING, path=PathType.DIRECT
                ),
                48.0,
            )
            runtime.set_peer(
                telio_node(
                    public_key="BBB", state=NodeState.CONNECTED, path=PathType.DIRECT
                ),
                49.0,
            )

            for future in futures:
                await future

        log_test_passed()

    @pytest.mark.asyncio
    async def test_derp_state(self) -> None:
        runtime = Runtime()
        events = Events(runtime)

        runtime.set_derp(create_derpserver_config(RelayState.CONNECTED))
        await events.wait_for_state_derp("1.1.1.1", [RelayState.CONNECTED], timeout=0.1)

        # It should pass again
        await events.wait_for_state_derp(
            "1.1.1.1",
            [RelayState.DISCONNECTED, RelayState.CONNECTING, RelayState.CONNECTED],
            timeout=0.1,
        )

        # it should fail (wrong state)
        with pytest.raises(asyncio.TimeoutError):
            await events.wait_for_state_derp(
                "1.1.1.1", [RelayState.DISCONNECTED], timeout=0.1
            )

        # it should fail (wrong IP)
        with pytest.raises(asyncio.TimeoutError):
            await events.wait_for_state_derp(
                "1.1.1.2", [RelayState.CONNECTED], timeout=0.1
            )

        log_test_passed()

    @pytest.mark.asyncio
    async def test_derp_change_state(self) -> None:
        runtime = Runtime()
        events = Events(runtime)

        runtime.set_derp(create_derpserver_config(RelayState.CONNECTED))
        await events.wait_for_state_derp("1.1.1.1", [RelayState.CONNECTED], timeout=0.1)

        runtime.set_derp(create_derpserver_config(RelayState.DISCONNECTED))
        await events.wait_for_state_derp(
            "1.1.1.1", [RelayState.DISCONNECTED], timeout=0.1
        )

        # It should pass again
        await events.wait_for_state_derp(
            "1.1.1.1",
            [RelayState.CONNECTED, RelayState.CONNECTING, RelayState.DISCONNECTED],
            timeout=0.1,
        )

        log_test_passed()

    @pytest.mark.asyncio
    async def test_derp_event(self) -> None:
        runtime = Runtime()
        events = Events(runtime)
        test_derp_server = create_derpserver_config(RelayState.CONNECTED)

        # Start waiting for new event before it is being generated
        async with run_async_context(
            events.wait_for_event_derp("1.1.1.1", [RelayState.CONNECTED], timeout=1)
        ) as future:
            # wait for futures to be started
            await asyncio.sleep(0)

            test_derp_server.ipv4 = "1.1.1.2"
            runtime.set_derp(copy.deepcopy(test_derp_server))
            with pytest.raises(asyncio.TimeoutError):
                await asyncio.wait_for(asyncio.shield(future), 0.1)

            test_derp_server.ipv4 = "1.1.1.1"
            test_derp_server.conn_state = RelayState.DISCONNECTED
            runtime.set_derp(copy.deepcopy(test_derp_server))
            with pytest.raises(asyncio.TimeoutError):
                await asyncio.wait_for(asyncio.shield(future), 0.1)

            test_derp_server.conn_state = RelayState.CONNECTING
            runtime.set_derp(copy.deepcopy(test_derp_server))
            with pytest.raises(asyncio.TimeoutError):
                await asyncio.wait_for(asyncio.shield(future), 0.1)

            test_derp_server.conn_state = RelayState.CONNECTED
            runtime.set_derp(copy.deepcopy(test_derp_server))
            await future

        with pytest.raises(asyncio.TimeoutError):
            await events.wait_for_event_derp(
                "1.1.1.1", [RelayState.CONNECTED], timeout=0.1
            )

        log_test_passed()

    @pytest.mark.asyncio
    async def test_derp_with_multiple_events(self) -> None:
        runtime = Runtime()
        events = Events(runtime)
        test_derp_server = create_derpserver_config(RelayState.CONNECTED)
        # Start waiting for new event before it is being generated
        async with run_async_contexts([
            events.wait_for_event_derp("1.1.1.1", [RelayState.DISCONNECTED], 5),
            events.wait_for_event_derp("1.1.1.1", [RelayState.CONNECTING], 5),
            events.wait_for_event_derp("1.1.1.1", [RelayState.CONNECTED], 5),
            events.wait_for_event_derp("1.1.1.2", [RelayState.DISCONNECTED], 5),
            events.wait_for_event_derp("1.1.1.2", [RelayState.CONNECTING], 5),
            events.wait_for_event_derp("1.1.1.2", [RelayState.CONNECTED], 5),
            events.wait_for_event_derp("1.1.1.3", [RelayState.DISCONNECTED], 5),
        ]) as futures:
            # wait for futures to be started
            await asyncio.sleep(0)

            test_derp_server.ipv4 = "1.1.1.3"
            test_derp_server.conn_state = RelayState.CONNECTED
            runtime.set_derp(copy.deepcopy(test_derp_server))

            test_derp_server.ipv4 = "1.1.1.4"
            runtime.set_derp(copy.deepcopy(test_derp_server))

            for future in futures:
                with pytest.raises(asyncio.TimeoutError):
                    await asyncio.wait_for(asyncio.shield(future), 0.1)

            test_derp_server.ipv4 = "1.1.1.1"
            test_derp_server.conn_state = RelayState.DISCONNECTED
            runtime.set_derp(copy.deepcopy(test_derp_server))
            test_derp_server.conn_state = RelayState.CONNECTING
            runtime.set_derp(copy.deepcopy(test_derp_server))
            test_derp_server.conn_state = RelayState.CONNECTED
            runtime.set_derp(copy.deepcopy(test_derp_server))

            test_derp_server.ipv4 = "1.1.1.2"
            test_derp_server.conn_state = RelayState.DISCONNECTED
            runtime.set_derp(copy.deepcopy(test_derp_server))
            test_derp_server.conn_state = RelayState.CONNECTING
            runtime.set_derp(copy.deepcopy(test_derp_server))
            test_derp_server.conn_state = RelayState.CONNECTED
            runtime.set_derp(copy.deepcopy(test_derp_server))

            test_derp_server.ipv4 = "1.1.1.3"
            test_derp_server.conn_state = RelayState.DISCONNECTED
            runtime.set_derp(copy.deepcopy(test_derp_server))

            for future in futures:
                await future

        log_test_passed()
