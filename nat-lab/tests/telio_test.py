import asyncio
import copy
import pytest
from telio import State, Runtime, Events, PeerInfo, PathType, DerpServer
from utils.asyncio_util import run_async_contexts, run_async_context


def create_derpserver_config(state: State) -> DerpServer:
    return DerpServer(
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

            assert runtime.handle_output_line("- started telio...")
            assert not runtime.handle_output_line("- started telio...")

            assert runtime.handle_output_line("natlab injected")
            assert not runtime.handle_output_line("natlab injected")

            for future in future_list:
                await future

    @pytest.mark.asyncio
    async def test_set_peer_state(self) -> None:
        runtime = Runtime()
        runtime.allowed_pub_keys = set(["AAA", "BBB"])

        runtime.set_peer(
            PeerInfo(public_key="AAA", state=State.Connected, path=PathType.Relay)
        )

        runtime.set_peer(
            PeerInfo(public_key="BBB", state=State.Disconnected, path=PathType.Direct)
        )

        await runtime.notify_peer_state("AAA", [State.Connected], [PathType.Relay])
        await runtime.notify_peer_state("BBB", [State.Disconnected], [PathType.Direct])

        # it should pass again
        await runtime.notify_peer_state(
            "AAA", [State.Connected], [PathType.Relay, PathType.Direct]
        )

        # it should fail (wrong state)
        with pytest.raises(asyncio.TimeoutError):
            await asyncio.wait_for(
                runtime.notify_peer_state("BBB", [State.Connected], [PathType.Direct]),
                0.1,
            )

        # it should fail (wrong path)
        with pytest.raises(asyncio.TimeoutError):
            await asyncio.wait_for(
                runtime.notify_peer_state("AAA", [State.Connected], [PathType.Direct]),
                0.1,
            )

    @pytest.mark.asyncio
    async def test_set_peer_event(self) -> None:
        runtime = Runtime()
        runtime.allowed_pub_keys = set(["AAA"])

        # Start waiting for new event before it is being generated
        async with run_async_context(
            runtime.notify_peer_event("AAA", [State.Connected], [PathType.Relay])
        ) as future:
            # wait for futures to be started
            await asyncio.sleep(0)
            runtime.set_peer(PeerInfo(public_key="AAA", state=State.Connected))
            await future

        with pytest.raises(asyncio.TimeoutError):
            await asyncio.wait_for(
                runtime.notify_peer_event("AAA", [State.Connected], [PathType.Relay]),
                0.1,
            )

    @pytest.mark.asyncio
    async def test_set_derp_state(self) -> None:
        runtime = Runtime()
        runtime.set_derp(create_derpserver_config(State.Connected))
        await runtime.notify_derp_state("1.1.1.1", [State.Connected])

        # it should pass again
        await runtime.notify_derp_state(
            "1.1.1.1",
            [State.Disconnected, State.Connecting, State.Connected],
        )

        # it should fail (wrong state)
        with pytest.raises(asyncio.TimeoutError):
            await asyncio.wait_for(
                runtime.notify_derp_state("1.1.1.1", [State.Disconnected]), 0.1
            )

        # it should fail (wrong IP)
        with pytest.raises(asyncio.TimeoutError):
            await asyncio.wait_for(
                runtime.notify_derp_state("1.1.1.2", [State.Connected]), 0.1
            )

    @pytest.mark.asyncio
    async def test_set_derp_event(self) -> None:
        runtime = Runtime()

        async with run_async_context(
            runtime.notify_derp_event("1.1.1.1", [State.Connected])
        ) as future:
            # wait for futures to be started
            await asyncio.sleep(0)
            runtime.set_derp(create_derpserver_config(State.Connected))
            await future

        with pytest.raises(asyncio.TimeoutError):
            await asyncio.wait_for(
                runtime.notify_derp_event("1.1.1.1", [State.Connected]), 0.1
            )

    @pytest.mark.asyncio
    async def test_handle_derp_event(self) -> None:
        runtime = Runtime()

        assert runtime.handle_output_line(
            '{"type":"relay","body":{"region_code":"test","name":"test","hostname"'
            + ':"test","ipv4":"1.1.1.1","relay_port":1111,"stun_port":1111,'
            + '"stun_plaintext_port":1111,"public_key":"test","weight":1,'
            + '"use_plain_text":true,"conn_state":"connected"}}'
        )

        await runtime.notify_derp_state("1.1.1.1", [State.Connected])

    @pytest.mark.asyncio
    async def test_handle_node_event(self) -> None:
        runtime = Runtime()
        runtime.allowed_pub_keys = set(["AAA"])

        assert runtime.handle_output_line(
            '{"type":"node","body":'
            + '{"identifier":"tcli","public_key":"AAA","state":"connected","is_exit":true,'
            + '"is_vpn":true,"ip_addresses":[],"allowed_ips":[],"endpoint":null,"hostname":null,'
            + '"allow_incoming_connections":false,"allow_peer_send_files":false,"path":"relay"}}'
        )

        await runtime.notify_peer_state(
            "AAA", [State.Connected], [PathType.Relay], is_exit=True, is_vpn=True
        )


class TestEvents:
    @pytest.mark.asyncio
    async def test_peer_state(self) -> None:
        runtime = Runtime()
        events = Events(runtime)

        runtime.allowed_pub_keys = set(["AAA", "BBB"])

        runtime.set_peer(
            PeerInfo(public_key="AAA", state=State.Connected, path=PathType.Relay)
        )
        runtime.set_peer(
            PeerInfo(public_key="BBB", state=State.Disconnected, path=PathType.Direct)
        )

        await events.wait_for_state_peer("AAA", [State.Connected], [PathType.Relay])
        await events.wait_for_state_peer("BBB", [State.Disconnected], [PathType.Direct])

        # it should pass again
        await events.wait_for_state_peer(
            "AAA", [State.Connected], [PathType.Relay, PathType.Direct]
        )
        await events.wait_for_state_peer(
            "BBB", [State.Disconnected], [PathType.Relay, PathType.Direct]
        )

        # it should fail (wrong state)
        with pytest.raises(asyncio.TimeoutError):
            await events.wait_for_state_peer(
                "BBB", [State.Connected], [PathType.Direct], timeout=0.1
            )

        # it should fail (wrong path)
        with pytest.raises(asyncio.TimeoutError):
            await events.wait_for_state_peer(
                "AAA", [State.Connected], [PathType.Direct], timeout=0.1
            )

    @pytest.mark.asyncio
    async def test_peer_change_state(self) -> None:
        runtime = Runtime()
        events = Events(runtime)
        runtime.allowed_pub_keys = set(["AAA", "BBB"])

        runtime.set_peer(PeerInfo(public_key="AAA", state=State.Connected))
        runtime.set_peer(PeerInfo(public_key="BBB", state=State.Connected))

        await events.wait_for_state_peer("BBB", [State.Connected], [PathType.Relay])
        await events.wait_for_state_peer("AAA", [State.Connected], [PathType.Relay])

        runtime.set_peer(PeerInfo(public_key="AAA", state=State.Disconnected))
        runtime.set_peer(PeerInfo(public_key="BBB", state=State.Disconnected))

        await events.wait_for_state_peer("BBB", [State.Disconnected], [PathType.Relay])
        await events.wait_for_state_peer("AAA", [State.Disconnected], [PathType.Relay])

        # It should pass again
        await events.wait_for_state_peer(
            "BBB", [State.Disconnected], [PathType.Relay, PathType.Direct]
        )
        await events.wait_for_state_peer(
            "AAA", [State.Disconnected], [PathType.Relay, PathType.Direct]
        )

        # it should fail (old state)
        with pytest.raises(asyncio.TimeoutError):
            await events.wait_for_state_peer(
                "BBB", [State.Connected], [PathType.Relay], timeout=0.1
            )

        # it should fail (wrong path)
        with pytest.raises(asyncio.TimeoutError):
            await events.wait_for_state_peer(
                "AAA", [State.Disconnected], [PathType.Direct], timeout=0.1
            )

    @pytest.mark.asyncio
    async def test_peer_event(self) -> None:
        runtime = Runtime()
        events = Events(runtime)
        runtime.allowed_pub_keys = set(["AAA", "BBB"])

        # Start waiting for new event before it is being generated
        async with run_async_context(
            events.wait_for_event_peer(
                "AAA", [State.Connected], [PathType.Relay], timeout=1
            )
        ) as future:
            # wait for futures to be started
            await asyncio.sleep(0)

            runtime.set_peer(PeerInfo(public_key="BBB", state=State.Connected))
            with pytest.raises(asyncio.TimeoutError):
                await asyncio.wait_for(asyncio.shield(future), 0.1)

            runtime.set_peer(PeerInfo(public_key="AAA", state=State.Disconnected))
            with pytest.raises(asyncio.TimeoutError):
                await asyncio.wait_for(asyncio.shield(future), 0.1)

            runtime.set_peer(PeerInfo(public_key="AAA", state=State.Connecting))
            with pytest.raises(asyncio.TimeoutError):
                await asyncio.wait_for(asyncio.shield(future), 0.1)

            runtime.set_peer(
                PeerInfo(public_key="AAA", state=State.Connected, path=PathType.Direct)
            )
            with pytest.raises(asyncio.TimeoutError):
                await asyncio.wait_for(asyncio.shield(future), 0.1)

            runtime.set_peer(PeerInfo(public_key="AAA", state=State.Connected))
            await future

        with pytest.raises(asyncio.TimeoutError):
            await events.wait_for_event_peer(
                "AAA", [State.Connected], [PathType.Relay], timeout=0.1
            )

    @pytest.mark.asyncio
    async def test_peer_with_multiple_events(self) -> None:
        runtime = Runtime()
        events = Events(runtime)
        runtime.allowed_pub_keys = set(["AAA", "BBB"])

        # Start waiting for new event before it is being generated
        async with run_async_contexts([
            events.wait_for_event_peer(
                "AAA", [State.Disconnected], [PathType.Relay], timeout=5
            ),
            events.wait_for_event_peer(
                "AAA", [State.Connecting], [PathType.Relay], timeout=5
            ),
            events.wait_for_event_peer(
                "AAA", [State.Connected], [PathType.Relay], timeout=5
            ),
            events.wait_for_event_peer(
                "BBB", [State.Disconnected], [PathType.Direct], timeout=5
            ),
            events.wait_for_event_peer(
                "BBB", [State.Connecting], [PathType.Direct], timeout=5
            ),
            events.wait_for_event_peer(
                "BBB", [State.Connected], [PathType.Direct], timeout=5
            ),
        ]) as futures:
            # wait for futures to be started
            await asyncio.sleep(0)

            runtime.set_peer(
                PeerInfo(public_key="BBB", state=State.Connected, path=PathType.Relay)
            )
            runtime.set_peer(
                PeerInfo(public_key="AAA", state=State.Connected, path=PathType.Direct)
            )
            for future in futures:
                with pytest.raises(asyncio.TimeoutError):
                    await asyncio.wait_for(asyncio.shield(future), 0.1)

            runtime.set_peer(
                PeerInfo(
                    public_key="AAA", state=State.Disconnected, path=PathType.Relay
                )
            )
            runtime.set_peer(
                PeerInfo(public_key="AAA", state=State.Connecting, path=PathType.Relay)
            )
            runtime.set_peer(
                PeerInfo(public_key="AAA", state=State.Connected, path=PathType.Relay)
            )
            runtime.set_peer(
                PeerInfo(
                    public_key="BBB", state=State.Disconnected, path=PathType.Direct
                )
            )
            runtime.set_peer(
                PeerInfo(public_key="BBB", state=State.Connecting, path=PathType.Direct)
            )
            runtime.set_peer(
                PeerInfo(public_key="BBB", state=State.Connected, path=PathType.Direct)
            )

            for future in futures:
                await future

    @pytest.mark.asyncio
    async def test_derp_state(self) -> None:
        runtime = Runtime()
        events = Events(runtime)

        runtime.set_derp(create_derpserver_config(State.Connected))
        await events.wait_for_state_derp("1.1.1.1", [State.Connected], timeout=0.1)

        # It should pass again
        await events.wait_for_state_derp(
            "1.1.1.1",
            [State.Disconnected, State.Connecting, State.Connected],
            timeout=0.1,
        )

        # it should fail (wrong state)
        with pytest.raises(asyncio.TimeoutError):
            await events.wait_for_state_derp(
                "1.1.1.1", [State.Disconnected], timeout=0.1
            )

        # it should fail (wrong IP)
        with pytest.raises(asyncio.TimeoutError):
            await events.wait_for_state_derp("1.1.1.2", [State.Connected], timeout=0.1)

    @pytest.mark.asyncio
    async def test_derp_change_state(self) -> None:
        runtime = Runtime()
        events = Events(runtime)

        runtime.set_derp(create_derpserver_config(State.Connected))
        await events.wait_for_state_derp("1.1.1.1", [State.Connected], timeout=0.1)

        runtime.set_derp(create_derpserver_config(State.Disconnected))
        await events.wait_for_state_derp("1.1.1.1", [State.Disconnected], timeout=0.1)

        # It should pass again
        await events.wait_for_state_derp(
            "1.1.1.1",
            [State.Connected, State.Connecting, State.Disconnected],
            timeout=0.1,
        )

    @pytest.mark.asyncio
    async def test_derp_event(self) -> None:
        runtime = Runtime()
        events = Events(runtime)
        test_derp_server = create_derpserver_config(State.Connected)

        # Start waiting for new event before it is being generated
        async with run_async_context(
            events.wait_for_event_derp("1.1.1.1", [State.Connected], timeout=1)
        ) as future:
            # wait for futures to be started
            await asyncio.sleep(0)

            test_derp_server.ipv4 = "1.1.1.2"
            runtime.set_derp(copy.deepcopy(test_derp_server))
            with pytest.raises(asyncio.TimeoutError):
                await asyncio.wait_for(asyncio.shield(future), 0.1)

            test_derp_server.ipv4 = "1.1.1.1"
            test_derp_server.conn_state = State.Disconnected
            runtime.set_derp(copy.deepcopy(test_derp_server))
            with pytest.raises(asyncio.TimeoutError):
                await asyncio.wait_for(asyncio.shield(future), 0.1)

            test_derp_server.conn_state = State.Connecting
            runtime.set_derp(copy.deepcopy(test_derp_server))
            with pytest.raises(asyncio.TimeoutError):
                await asyncio.wait_for(asyncio.shield(future), 0.1)

            test_derp_server.conn_state = State.Connected
            runtime.set_derp(copy.deepcopy(test_derp_server))
            await future

        with pytest.raises(asyncio.TimeoutError):
            await events.wait_for_event_derp("1.1.1.1", [State.Connected], timeout=0.1)

    @pytest.mark.asyncio
    async def test_derp_with_multiple_events(self) -> None:
        runtime = Runtime()
        events = Events(runtime)
        test_derp_server = create_derpserver_config(State.Connected)
        # Start waiting for new event before it is being generated
        async with run_async_contexts([
            events.wait_for_event_derp("1.1.1.1", [State.Disconnected], 5),
            events.wait_for_event_derp("1.1.1.1", [State.Connecting], 5),
            events.wait_for_event_derp("1.1.1.1", [State.Connected], 5),
            events.wait_for_event_derp("1.1.1.2", [State.Disconnected], 5),
            events.wait_for_event_derp("1.1.1.2", [State.Connecting], 5),
            events.wait_for_event_derp("1.1.1.2", [State.Connected], 5),
            events.wait_for_event_derp("1.1.1.3", [State.Disconnected], 5),
        ]) as futures:
            # wait for futures to be started
            await asyncio.sleep(0)

            test_derp_server.ipv4 = "1.1.1.3"
            test_derp_server.conn_state = State.Connected
            runtime.set_derp(copy.deepcopy(test_derp_server))

            test_derp_server.ipv4 = "1.1.1.4"
            runtime.set_derp(copy.deepcopy(test_derp_server))

            for future in futures:
                with pytest.raises(asyncio.TimeoutError):
                    await asyncio.wait_for(asyncio.shield(future), 0.1)

            test_derp_server.ipv4 = "1.1.1.1"
            test_derp_server.conn_state = State.Disconnected
            runtime.set_derp(copy.deepcopy(test_derp_server))
            test_derp_server.conn_state = State.Connecting
            runtime.set_derp(copy.deepcopy(test_derp_server))
            test_derp_server.conn_state = State.Connected
            runtime.set_derp(copy.deepcopy(test_derp_server))

            test_derp_server.ipv4 = "1.1.1.2"
            test_derp_server.conn_state = State.Disconnected
            runtime.set_derp(copy.deepcopy(test_derp_server))
            test_derp_server.conn_state = State.Connecting
            runtime.set_derp(copy.deepcopy(test_derp_server))
            test_derp_server.conn_state = State.Connected
            runtime.set_derp(copy.deepcopy(test_derp_server))

            test_derp_server.ipv4 = "1.1.1.3"
            test_derp_server.conn_state = State.Disconnected
            runtime.set_derp(copy.deepcopy(test_derp_server))

            for future in futures:
                await future
