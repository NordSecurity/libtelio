import asyncio
import copy
import pytest
from telio import State, Runtime, Events, PeerInfo, PathType, DerpServer
from utils import testing
from utils.asyncio_util import run_async_contexts, run_async_context


class TestRuntime:
    @pytest.mark.asyncio
    async def test_wait_output(self) -> None:
        runtime = Runtime()

        async def wait_output(what: str) -> None:
            event = asyncio.Event()
            runtime.get_output_notifier().notify_output(what, event)
            await testing.wait_short(event.wait())

        async with run_async_contexts(
            [
                wait_output("started telio"),
                wait_output("started"),
                wait_output("natlab injected"),
            ]
        ) as future_list:
            await asyncio.sleep(0)

            assert runtime.handle_output_line("- started telio...")
            assert not runtime.handle_output_line("- started telio...")

            assert runtime.handle_output_line("natlab injected")
            assert not runtime.handle_output_line("natlab injected")

            for future in future_list:
                await testing.wait_short(future)

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

        await testing.wait_short(
            runtime.notify_peer_state("AAA", [State.Connected], [PathType.Relay])
        )

        await testing.wait_short(
            runtime.notify_peer_state("BBB", [State.Disconnected], [PathType.Direct])
        )

        # it should pass again
        await testing.wait_short(
            runtime.notify_peer_state(
                "AAA", [State.Connected], [PathType.Relay, PathType.Direct]
            )
        )

        # it should fail (wrong state)
        with pytest.raises(asyncio.TimeoutError):
            await testing.wait_short(
                runtime.notify_peer_state("BBB", [State.Connected], [PathType.Direct])
            )

        # it should fail (wrong path)
        with pytest.raises(asyncio.TimeoutError):
            await testing.wait_short(
                runtime.notify_peer_state("AAA", [State.Connected], [PathType.Direct])
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
            await testing.wait_short(future)

        with pytest.raises(asyncio.TimeoutError):
            await testing.wait_short(
                runtime.notify_peer_event("AAA", [State.Connected], [PathType.Relay])
            )

    @pytest.mark.asyncio
    async def test_set_derp_state(self) -> None:
        runtime = Runtime()

        runtime.set_derp(
            DerpServer(
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
                conn_state=State.Connected,
            )
        )

        await testing.wait_short(
            runtime.notify_derp_state("1.1.1.1", [State.Connected])
        )

        # it should pass again
        await testing.wait_short(
            runtime.notify_derp_state(
                "1.1.1.1", [State.Disconnected, State.Connecting, State.Connected]
            )
        )

        # it should fail (wrong state)
        with pytest.raises(asyncio.TimeoutError):
            await testing.wait_short(
                runtime.notify_derp_state("1.1.1.1", [State.Disconnected])
            )

        # it should fail (wrong IP)
        with pytest.raises(asyncio.TimeoutError):
            await testing.wait_short(
                runtime.notify_derp_state("1.1.1.2", [State.Connected])
            )

    @pytest.mark.asyncio
    async def test_set_derp_event(self) -> None:
        runtime = Runtime()

        async with run_async_context(
            runtime.notify_derp_event("1.1.1.1", [State.Connected])
        ) as future:
            # wait for futures to be started
            await asyncio.sleep(0)
            runtime.set_derp(
                DerpServer(
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
                    conn_state=State.Connected,
                )
            )
            await testing.wait_short(future)

        with pytest.raises(asyncio.TimeoutError):
            await testing.wait_short(
                runtime.notify_derp_event("1.1.1.1", [State.Connected])
            )

    @pytest.mark.asyncio
    async def test_handle_derp_event(self) -> None:
        runtime = Runtime()

        assert runtime.handle_output_line(
            "event relay:"
            ' {"region_code":"test","name":"test","hostname":"test","ipv4":"1.1.1.1","relay_port":1111,"stun_port":1111,"stun_plaintext_port":1111,"public_key":"test","weight":1,"use_plain_text":true,"conn_state":"connected"}'
        )

        await testing.wait_short(
            runtime.notify_derp_state("1.1.1.1", [State.Connected])
        )

    @pytest.mark.asyncio
    async def test_handle_node_event(self) -> None:
        runtime = Runtime()
        runtime.allowed_pub_keys = set(["AAA"])

        assert runtime.handle_output_line(
            "event node:"
            ' "{"identifier":"tcli","public_key":"AAA","state":"connected","is_exit":true,"is_vpn":true,"ip_addresses":[],"allowed_ips":[],"endpoint":null,"hostname":null,"allow_incoming_connections":false,"allow_peer_send_files":false,"path":"relay"}"'
        )

        await testing.wait_short(
            runtime.notify_peer_state("AAA", [State.Connected], [PathType.Relay])
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

        await testing.wait_short(
            events.wait_for_state_peer("AAA", [State.Connected], [PathType.Relay])
        )

        await testing.wait_short(
            events.wait_for_state_peer("BBB", [State.Disconnected], [PathType.Direct])
        )

        # it should pass again
        await testing.wait_short(
            events.wait_for_state_peer(
                "AAA", [State.Connected], [PathType.Relay, PathType.Direct]
            )
        )
        await testing.wait_short(
            events.wait_for_state_peer(
                "BBB", [State.Disconnected], [PathType.Relay, PathType.Direct]
            )
        )

        # it should fail (wrong state)
        with pytest.raises(asyncio.TimeoutError):
            await testing.wait_short(
                events.wait_for_state_peer("BBB", [State.Connected], [PathType.Direct])
            )

        # it should fail (wrong path)
        with pytest.raises(asyncio.TimeoutError):
            await testing.wait_short(
                events.wait_for_state_peer("AAA", [State.Connected], [PathType.Direct])
            )

    @pytest.mark.asyncio
    async def test_peer_change_state(self) -> None:
        runtime = Runtime()
        events = Events(runtime)
        runtime.allowed_pub_keys = set(["AAA", "BBB"])

        runtime.set_peer(PeerInfo(public_key="AAA", state=State.Connected))
        runtime.set_peer(PeerInfo(public_key="BBB", state=State.Connected))

        await testing.wait_short(
            events.wait_for_state_peer("BBB", [State.Connected], [PathType.Relay])
        )
        await testing.wait_short(
            events.wait_for_state_peer("AAA", [State.Connected], [PathType.Relay])
        )

        runtime.set_peer(PeerInfo(public_key="AAA", state=State.Disconnected))
        runtime.set_peer(PeerInfo(public_key="BBB", state=State.Disconnected))

        await testing.wait_short(
            events.wait_for_state_peer("BBB", [State.Disconnected], [PathType.Relay])
        )
        await testing.wait_short(
            events.wait_for_state_peer("AAA", [State.Disconnected], [PathType.Relay])
        )

        # It should pass again
        await testing.wait_short(
            events.wait_for_state_peer(
                "BBB", [State.Disconnected], [PathType.Relay, PathType.Direct]
            )
        )
        await testing.wait_short(
            events.wait_for_state_peer(
                "AAA", [State.Disconnected], [PathType.Relay, PathType.Direct]
            )
        )

        # it should fail (old state)
        with pytest.raises(asyncio.TimeoutError):
            await testing.wait_short(
                events.wait_for_state_peer("BBB", [State.Connected], [PathType.Relay])
            )

        # it should fail (wrong path)
        with pytest.raises(asyncio.TimeoutError):
            await testing.wait_short(
                events.wait_for_state_peer(
                    "AAA", [State.Disconnected], [PathType.Direct]
                )
            )

    @pytest.mark.asyncio
    async def test_peer_event(self) -> None:
        runtime = Runtime()
        events = Events(runtime)
        runtime.allowed_pub_keys = set(["AAA", "BBB"])

        # Start waiting for new event before it is being generated
        async with run_async_context(
            events.wait_for_event_peer("AAA", [State.Connected], [PathType.Relay])
        ) as future:
            # wait for futures to be started
            await asyncio.sleep(0)

            runtime.set_peer(PeerInfo(public_key="BBB", state=State.Connected))
            with pytest.raises(asyncio.TimeoutError):
                await testing.wait_short(asyncio.shield(future))

            runtime.set_peer(PeerInfo(public_key="AAA", state=State.Disconnected))
            with pytest.raises(asyncio.TimeoutError):
                await testing.wait_short(asyncio.shield(future))

            runtime.set_peer(PeerInfo(public_key="AAA", state=State.Connecting))
            with pytest.raises(asyncio.TimeoutError):
                await testing.wait_short(asyncio.shield(future))

            runtime.set_peer(
                PeerInfo(public_key="AAA", state=State.Connected, path=PathType.Direct)
            )
            with pytest.raises(asyncio.TimeoutError):
                await testing.wait_short(asyncio.shield(future))

            runtime.set_peer(PeerInfo(public_key="AAA", state=State.Connected))
            await testing.wait_short(future)

        with pytest.raises(asyncio.TimeoutError):
            await testing.wait_short(
                events.wait_for_event_peer("AAA", [State.Connected], [PathType.Relay])
            )

    @pytest.mark.asyncio
    async def test_peer_with_multiple_events(self) -> None:
        runtime = Runtime()
        events = Events(runtime)
        runtime.allowed_pub_keys = set(["AAA", "BBB"])

        # Start waiting for new event before it is being generated
        async with run_async_contexts(
            [
                events.wait_for_event_peer(
                    "AAA", [State.Disconnected], [PathType.Relay]
                ),
                events.wait_for_event_peer("AAA", [State.Connecting], [PathType.Relay]),
                events.wait_for_event_peer("AAA", [State.Connected], [PathType.Relay]),
                events.wait_for_event_peer(
                    "BBB", [State.Disconnected], [PathType.Direct]
                ),
                events.wait_for_event_peer(
                    "BBB", [State.Connecting], [PathType.Direct]
                ),
                events.wait_for_event_peer("BBB", [State.Connected], [PathType.Direct]),
            ]
        ) as futures:
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
                    await testing.wait_short(asyncio.shield(future))

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
                await testing.wait_short(future)

    @pytest.mark.asyncio
    async def test_derp_state(self) -> None:
        runtime = Runtime()
        events = Events(runtime)

        runtime.set_derp(
            DerpServer(
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
                conn_state=State.Connected,
            )
        )

        await testing.wait_short(
            events.wait_for_state_derp("1.1.1.1", [State.Connected])
        )

        # It should pass again
        await testing.wait_short(
            events.wait_for_state_derp(
                "1.1.1.1", [State.Disconnected, State.Connecting, State.Connected]
            )
        )

        # it should fail (wrong state)
        with pytest.raises(asyncio.TimeoutError):
            await testing.wait_short(
                events.wait_for_state_derp("1.1.1.1", [State.Disconnected])
            )

        # it should fail (wrong IP)
        with pytest.raises(asyncio.TimeoutError):
            await testing.wait_short(
                events.wait_for_state_derp("1.1.1.2", [State.Connected])
            )

    @pytest.mark.asyncio
    async def test_derp_change_state(self) -> None:
        runtime = Runtime()
        events = Events(runtime)

        runtime.set_derp(
            DerpServer(
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
                conn_state=State.Connected,
            )
        )

        await testing.wait_short(
            events.wait_for_state_derp("1.1.1.1", [State.Connected])
        )

        runtime.set_derp(
            DerpServer(
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
                conn_state=State.Disconnected,
            )
        )

        await testing.wait_short(
            events.wait_for_state_derp("1.1.1.1", [State.Disconnected])
        )

        # It should pass again
        await testing.wait_short(
            events.wait_for_state_derp(
                "1.1.1.1", [State.Connected, State.Connecting, State.Disconnected]
            )
        )

    @pytest.mark.asyncio
    async def test_derp_event(self) -> None:
        runtime = Runtime()
        events = Events(runtime)
        test_derp_server = DerpServer(
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
            conn_state=State.Connected,
        )

        # Start waiting for new event before it is being generated
        async with run_async_context(
            events.wait_for_event_derp("1.1.1.1", [State.Connected])
        ) as future:
            # wait for futures to be started
            await asyncio.sleep(0)

            test_derp_server.ipv4 = "1.1.1.2"
            runtime.set_derp(copy.deepcopy(test_derp_server))
            with pytest.raises(asyncio.TimeoutError):
                await testing.wait_short(asyncio.shield(future))

            test_derp_server.ipv4 = "1.1.1.1"
            test_derp_server.conn_state = State.Disconnected
            runtime.set_derp(copy.deepcopy(test_derp_server))
            with pytest.raises(asyncio.TimeoutError):
                await testing.wait_short(asyncio.shield(future))

            test_derp_server.conn_state = State.Connecting
            runtime.set_derp(copy.deepcopy(test_derp_server))
            with pytest.raises(asyncio.TimeoutError):
                await testing.wait_short(asyncio.shield(future))

            test_derp_server.conn_state = State.Connected
            runtime.set_derp(copy.deepcopy(test_derp_server))
            await testing.wait_short(future)

        with pytest.raises(asyncio.TimeoutError):
            await testing.wait_short(
                events.wait_for_event_derp("1.1.1.1", [State.Connected])
            )

    @pytest.mark.asyncio
    async def test_derp_with_multiple_events(self) -> None:
        runtime = Runtime()
        events = Events(runtime)
        test_derp_server = DerpServer(
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
            conn_state=State.Connected,
        )
        # Start waiting for new event before it is being generated
        async with run_async_contexts(
            [
                events.wait_for_event_derp("1.1.1.1", [State.Disconnected]),
                events.wait_for_event_derp("1.1.1.1", [State.Connecting]),
                events.wait_for_event_derp("1.1.1.1", [State.Connected]),
                events.wait_for_event_derp("1.1.1.2", [State.Disconnected]),
                events.wait_for_event_derp("1.1.1.2", [State.Connecting]),
                events.wait_for_event_derp("1.1.1.2", [State.Connected]),
                events.wait_for_event_derp("1.1.1.3", [State.Disconnected]),
            ]
        ) as futures:
            # wait for futures to be started
            await asyncio.sleep(0)

            test_derp_server.ipv4 = "1.1.1.3"
            test_derp_server.conn_state = State.Connected
            runtime.set_derp(copy.deepcopy(test_derp_server))

            test_derp_server.ipv4 = "1.1.1.4"
            runtime.set_derp(copy.deepcopy(test_derp_server))

            for future in futures:
                with pytest.raises(asyncio.TimeoutError):
                    await testing.wait_short(asyncio.shield(future))

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
                await testing.wait_short(future)
