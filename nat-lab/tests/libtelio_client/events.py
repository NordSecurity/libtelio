import asyncio
from tests.config import DERP_SERVERS
from tests.uniffi import VpnConnectionError
from tests.utils import asyncio_util
from tests.utils.bindings import ErrorEvent, LinkState, NodeState, PathType, RelayState
from tests.utils.command_grepper import CommandGrepper
from tests.utils.connection import TargetOS
from tests.utils.logger import log
from typing import List, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from tests.libtelio_client.client import Client


class ClientEvents:
    """Event/state waiting helpers for a running `Client`.

    Holds a back-reference to its `Client` and delegates to the underlying
    `Events`/`Runtime` (via `client.get_events()`), adding per-node logging and
    default-path handling. Accessed as `client.events`.
    """

    def __init__(self, client: "Client") -> None:
        self._client = client

    async def wait_for_state_peer(
        self,
        public_key,
        states: List[NodeState],
        paths: Optional[List[PathType]] = None,
        is_exit: bool = False,
        is_vpn: bool = False,
        timeout: Optional[float] = None,
        link_state: Optional[LinkState] = None,
        vpn_connection_error: Optional[VpnConnectionError] = None,
    ) -> None:
        info = f"peer({public_key}) with states({states}), paths({paths}), is_exit({is_exit}), is_vpn({is_vpn}), link_state({link_state}), vpn_connection_error({vpn_connection_error})"

        log.debug("[%s]: wait for peer state %s", self._client.node.name, info)
        await self._client.get_events().wait_for_state_peer(
            public_key,
            states,
            paths if paths else [PathType.RELAY],
            is_exit,
            is_vpn,
            timeout,
            link_state,
            vpn_connection_error,
        )

    async def wait_for_link_state(
        self,
        public_key: str,
        state: LinkState,
        timeout: Optional[float] = None,
    ) -> None:
        """Wait until a link_state event matching the `state` for `public_key` is available."""
        info = f"peer({public_key}) with state({state})"

        log.debug("[%s]: wait for link state %s", self._client.node.name, info)
        await self._client.get_events().wait_for_link_state(
            public_key,
            state,
            timeout,
        )

    async def wait_for_event_peer(
        self,
        public_key: str,
        states: List[NodeState],
        paths: Optional[List[PathType]] = None,
        is_exit: bool = False,
        is_vpn: bool = False,
        timeout: Optional[float] = None,
        link_state: Optional[LinkState] = None,
    ) -> None:
        event_info = f"peer({public_key}) with states({states}), paths({paths}), link_state({link_state}), is_exit={is_exit}, is_vpn={is_vpn}"

        log.debug("[%s]: wait for peer event %s", self._client.node.name, event_info)
        await self._client.get_events().wait_for_event_peer(
            public_key,
            states,
            paths if paths else [PathType.RELAY],
            is_exit,
            is_vpn,
            timeout,
            link_state,
        )
        log.debug("[%s]: got peer event %s", self._client.node.name, event_info)

    async def wait_for_future_event_peer(
        self,
        public_key: str,
        states: List[NodeState],
        duration_from_now: float,
        paths: Optional[List[PathType]] = None,
        is_exit: bool = False,
        is_vpn: bool = False,
    ) -> None:
        """
        Wait for a matching event, until it occurs or throw an WontHappenError if it's guaranteed it will not happen.

        This method is useful to avoid problem related to transient netwroking issues which can delay events by few seconds.
        It uses the timestamps of events generated on the remote side where libtelio is located, instead of using the local
        time of receiving of event.
        """
        event_info = f"peer({public_key}) with states({states}), duration_from_now={duration_from_now}, paths({paths}), is_exit={is_exit}, is_vpn={is_vpn}"

        log.debug("[%s]: wait for peer event %s", self._client.node.name, event_info)
        await self._client.get_events().wait_for_future_event_peer(
            public_key,
            states,
            duration_from_now,
            paths if paths else [PathType.RELAY],
            is_exit,
            is_vpn,
        )
        log.debug("[%s]: got peer event %s", self._client.node.name, event_info)

    def get_link_state_events(self, public_key: str) -> List[LinkState]:
        return self._client.get_events().get_link_state_events(public_key)

    async def wait_for_state_derp(
        self, derp_ip, states: List[RelayState], timeout: Optional[float] = None
    ) -> None:
        await self._client.get_events().wait_for_state_derp(derp_ip, states, timeout)

    async def wait_for_state_on_any_derp(
        self, states: List[RelayState], timeout: Optional[float] = None
    ) -> None:
        async with asyncio_util.run_async_contexts([
            self._client.get_events().wait_for_state_derp(
                str(derp.ipv4), states, timeout
            )
            for derp in DERP_SERVERS
        ]) as futures:
            try:
                while not any(fut.done() for fut in futures):
                    await asyncio.sleep(0.01)
            except asyncio.CancelledError:
                pass

    async def wait_for_every_derp_disconnection(
        self, timeout: Optional[float] = None
    ) -> None:
        async with asyncio_util.run_async_contexts([
            self._client.get_events().wait_for_state_derp(
                str(derp.ipv4),
                [RelayState.DISCONNECTED, RelayState.CONNECTING],
                timeout,
            )
            for derp in DERP_SERVERS
        ]) as futures:
            try:
                while not all(fut.done() for fut in futures):
                    await asyncio.sleep(0.1)
            except asyncio.CancelledError:
                pass

    async def wait_for_event_derp(
        self, derp_ip, states: List[RelayState], timeout: Optional[float] = None
    ) -> None:
        event_info = f"derp({derp_ip}) with states({states})"

        log.debug("[%s]: wait for derp event %s", self._client.node.name, event_info)
        await self._client.get_events().wait_for_event_derp(derp_ip, states, timeout)
        log.debug("[%s]: got derp event %s", self._client.node.name, event_info)

    async def wait_for_event_on_any_derp(
        self, states: List[RelayState], timeout: Optional[float] = None
    ) -> None:
        async with asyncio_util.run_async_contexts([
            self._client.get_events().wait_for_event_derp(
                str(derp.ipv4), states, timeout
            )
            for derp in DERP_SERVERS
        ]) as futures:
            try:
                while not any(fut.done() for fut in futures):
                    await asyncio.sleep(0.1)
            except asyncio.CancelledError:
                pass

    async def wait_for_event_error(self, err: ErrorEvent):
        await self._client.get_events().wait_for_event_error(err)

    async def wait_for_listen_port_ready(
        self,
        protocol: str,
        port: int,
        process: str = "python3",
        timeout: Optional[float] = None,
    ) -> None:
        assert (
            self._client.get_connection().target_os == TargetOS.Linux
        ), "Waiting for listen ports is supported only on Linux hosts"

        if not await CommandGrepper(
            self._client.get_connection(),
            [
                "netstat",
                "-lpn",
            ],
            timeout,
        ).check_exists(f":{port} ", [protocol, process]):
            raise RuntimeError("Listening socket could not be found")
