from utils.asyncio_util import run_async_contexts, run_async_context
from telio import State, Runtime, Events, PeerInfo, PathType, DerpServer
import asyncio
import pytest
import utils.testing as testing


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

        runtime.allowed_pub_keys = set(["AAA"])

        runtime._set_peer(PeerInfo(public_key="AAA", state=State.Connected))
        await testing.wait_short(
            runtime.notify_peer_state(
                "AAA", [State.Connected], [PathType.Relay, PathType.Direct]
            )
        )

        peer_info = runtime.get_peer_info("AAA")
        assert peer_info is not None and peer_info.state == State.Connected

    @pytest.mark.asyncio
    async def test_set_derp_state(self) -> None:
        runtime = Runtime()
        runtime._set_derp(
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

        derp_info = runtime.get_derp_info("1.1.1.1")
        assert derp_info is not None and derp_info.conn_state == State.Connected

    @pytest.mark.asyncio
    async def test_handle_derp_event(self) -> None:
        runtime = Runtime()
        assert runtime.handle_output_line(
            'event relay: {"region_code":"test","name":"test","hostname":"test","ipv4":"1.1.1.1","relay_port":1111,"stun_port":1111,"stun_plaintext_port":1111,"public_key":"test","weight":1,"use_plain_text":true,"conn_state":"connected"}'
        )
        await testing.wait_short(
            runtime.notify_derp_state("1.1.1.1", [State.Connected])
        )
        derp_info = runtime.get_derp_info("1.1.1.1")
        assert derp_info is not None and derp_info.conn_state == State.Connected

    @pytest.mark.asyncio
    async def test_handle_node_event(self) -> None:
        runtime = Runtime()
        runtime.allowed_pub_keys = set(["AAA"])
        assert runtime.handle_output_line(
            'event node: "{"identifier":"tcli","public_key":"AAA","state":"connected","is_exit":true,"is_vpn":true,"ip_addresses":[],"allowed_ips":[],"endpoint":null,"hostname":null,"allow_incoming_connections":false,"allow_peer_send_files":false,"path":"relay"}"'
        )
        peer_info = runtime.get_peer_info("AAA")
        assert peer_info is not None and peer_info.state == State.Connected


class TestEvents:
    @pytest.mark.asyncio
    async def test_peer_state(self) -> None:
        runtime = Runtime()
        events = Events(runtime)

        runtime.allowed_pub_keys = set(["AAA", "BBB"])
        runtime._set_peer(PeerInfo(public_key="AAA", state=State.Connected))
        runtime._set_peer(PeerInfo(public_key="BBB", state=State.Connected))

        await testing.wait_short(
            asyncio.gather(
                events.wait_for_peer_state(
                    "BBB", [State.Connected], [PathType.Relay, PathType.Direct]
                ),
                events.wait_for_peer_state("AAA", [State.Connected], [PathType.Relay]),
            )
        )

        # Handshake already achieved, should return immediately
        await testing.wait_short(
            asyncio.gather(
                events.wait_for_peer_state(
                    "BBB", [State.Connected], [PathType.Relay, PathType.Direct]
                ),
                events.wait_for_peer_state("AAA", [State.Connected], [PathType.Relay]),
            )
        )

        # This should timeout even though handshake already achieved, since no new event is generated
        with pytest.raises(asyncio.TimeoutError):
            await testing.wait_short(
                events.wait_for_new_peer_state(
                    "BBB",
                    [State.Connected],
                    [PathType.Relay, PathType.Direct],
                ),
            )

        # This should timeout even though handshake already achieved, since no new event is generated
        with pytest.raises(asyncio.TimeoutError):
            await testing.wait_short(
                events.wait_for_new_peer_state(
                    "AAA",
                    [State.Connected],
                    [PathType.Relay],
                )
            )

    @pytest.mark.asyncio
    async def test_explicit_new_peer_state(self) -> None:
        runtime = Runtime()
        events = Events(runtime)

        runtime.allowed_pub_keys = set(["AAA", "BBB"])
        runtime._set_peer(PeerInfo(public_key="AAA", state=State.Connected))
        runtime._set_peer(PeerInfo(public_key="BBB", state=State.Connected))

        await testing.wait_short(
            asyncio.gather(
                events.wait_for_peer_state("BBB", [State.Connected], [PathType.Relay]),
                events.wait_for_peer_state("AAA", [State.Connected], [PathType.Relay]),
            )
        )

        # Handshake already achieved, should return immediately
        await testing.wait_short(
            asyncio.gather(
                events.wait_for_peer_state("BBB", [State.Connected], [PathType.Relay]),
                events.wait_for_peer_state("AAA", [State.Connected], [PathType.Relay]),
            )
        )

        # Start waiting for new event before it is being generated
        async with run_async_contexts(
            [
                events.wait_for_new_peer_state(
                    "BBB",
                    [State.Disconnected],
                    [PathType.Relay],
                ),
                events.wait_for_new_peer_state(
                    "AAA",
                    [State.Disconnected],
                    [PathType.Relay],
                ),
            ]
        ) as futures:
            # wait for futures to be started
            await asyncio.sleep(0)
            runtime._set_peer(PeerInfo(public_key="AAA", state=State.Disconnected))
            runtime._set_peer(PeerInfo(public_key="BBB", state=State.Disconnected))
            for future in futures:
                await testing.wait_short(future)

    @pytest.mark.asyncio
    async def test_peer_change_state(self) -> None:
        runtime = Runtime()
        events = Events(runtime)

        runtime.allowed_pub_keys = set(["AAA", "BBB"])
        runtime._set_peer(PeerInfo(public_key="AAA", state=State.Connected))
        runtime._set_peer(PeerInfo(public_key="BBB", state=State.Connected))

        await testing.wait_short(
            asyncio.gather(
                events.wait_for_peer_state(
                    "BBB", [State.Connected], [PathType.Relay, PathType.Direct]
                ),
                events.wait_for_peer_state("AAA", [State.Connected], [PathType.Relay]),
            )
        )

        # Handshake already achieved, should return immediately
        await testing.wait_short(
            asyncio.gather(
                events.wait_for_peer_state(
                    "BBB", [State.Connected], [PathType.Relay, PathType.Direct]
                ),
                events.wait_for_peer_state("AAA", [State.Connected], [PathType.Relay]),
            )
        )

        # This should timeout even though handshake already achieved, since no new event is generated
        with pytest.raises(asyncio.TimeoutError):
            await testing.wait_short(
                events.wait_for_new_peer_state(
                    "BBB",
                    [State.Connected],
                    [PathType.Relay, PathType.Direct],
                ),
            )

        # This should timeout even though handshake already achieved, since no new event is generated
        with pytest.raises(asyncio.TimeoutError):
            await testing.wait_short(
                events.wait_for_new_peer_state(
                    "AAA",
                    [State.Connected],
                    [PathType.Relay],
                ),
            )

        runtime._set_peer(PeerInfo(public_key="AAA", state=State.Disconnected))
        runtime._set_peer(PeerInfo(public_key="BBB", state=State.Disconnected))

        # check for changed state
        await testing.wait_short(
            asyncio.gather(
                events.wait_for_peer_state(
                    "BBB", [State.Disconnected], [PathType.Relay, PathType.Direct]
                ),
                events.wait_for_peer_state(
                    "AAA", [State.Disconnected], [PathType.Relay]
                ),
            )
        )

        # check if state is truly changed and does not return at all on old state
        with pytest.raises(asyncio.TimeoutError):
            await testing.wait_short(
                events.wait_for_peer_state(
                    "BBB", [State.Connected], [PathType.Relay, PathType.Direct]
                )
            )

        # check for old and new state, should return immediately
        await testing.wait_short(
            events.wait_for_peer_state(
                "AAA", [State.Connected, State.Disconnected], [PathType.Relay]
            )
        )

    @pytest.mark.asyncio
    async def test_derp_state(self) -> None:
        runtime = Runtime()
        events = Events(runtime)

        runtime._set_derp(
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
            events.wait_for_derp_state("1.1.1.1", [State.Connected]),
        )

        # Connection already achieved, should return immediately
        await testing.wait_short(
            events.wait_for_derp_state("1.1.1.1", [State.Connected]),
        )

        # This should timeout even though derp connection state is connected, since no new event is generated
        with pytest.raises(asyncio.TimeoutError):
            await testing.wait_short(
                events.wait_for_new_derp_state("1.1.1.1", [State.Connected])
            )

    @pytest.mark.asyncio
    async def test_explicit_new_derp_state(self) -> None:
        runtime = Runtime()
        events = Events(runtime)

        runtime._set_derp(
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
            events.wait_for_derp_state("1.1.1.1", [State.Connected]),
        )

        # Connection already achieved, should return immediately
        await testing.wait_short(
            events.wait_for_derp_state("1.1.1.1", [State.Connected]),
        )

        # This should timeout even though derp connection state is connected, since no new event is generated
        with pytest.raises(asyncio.TimeoutError):
            await testing.wait_short(
                events.wait_for_new_derp_state("1.1.1.1", [State.Connected])
            )

        # Start waiting for new event before it is being generated
        async with run_async_context(
            events.wait_for_derp_state("1.1.1.1", [State.Disconnected])
        ) as future:
            # wait for futures to be started
            await asyncio.sleep(0)
            runtime._set_derp(
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
            await testing.wait_short(future)

    @pytest.mark.asyncio
    async def test_derp_change_state(self) -> None:
        runtime = Runtime()
        events = Events(runtime)

        runtime._set_derp(
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
            events.wait_for_derp_state("1.1.1.1", [State.Connected]),
        )

        # Connection already achieved, should return immediately
        await testing.wait_short(
            events.wait_for_derp_state("1.1.1.1", [State.Connected]),
        )

        # This should timeout even though derp connection state is connected, since no new event is generated
        with pytest.raises(asyncio.TimeoutError):
            await testing.wait_short(
                events.wait_for_new_derp_state("1.1.1.1", [State.Connected])
            )

        runtime._set_derp(
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

        # check for changed state
        await testing.wait_short(
            events.wait_for_derp_state("1.1.1.1", [State.Disconnected]),
        )

        # check for old and new state, should return immediately
        await testing.wait_short(
            events.wait_for_derp_state(
                "1.1.1.1", [State.Disconnected, State.Connected]
            ),
        )

        # check if state is truly changed and does not return at all on old state
        with pytest.raises(asyncio.TimeoutError):
            await testing.wait_short(
                events.wait_for_derp_state("1.1.1.1", [State.Connected]),
            )
