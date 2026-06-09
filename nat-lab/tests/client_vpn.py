import asyncio
from tests.utils import asyncio_util
from tests.utils.bindings import LinkState, NodeState, PathType
from typing import Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from tests.telio import Client


class ClientVpn:
    """VPN / exit-node connection control for a `Client`.

    Holds a back-reference to its `Client` and orchestrates interface setup,
    routing, the libtelio proxy and event waiting. Accessed as `client.vpn`.
    """

    def __init__(self, client: "Client") -> None:
        self._client = client

    async def connect_to_vpn(
        self,
        ip: str,
        port: int,
        public_key: str,
        timeout: Optional[float] = None,
        pq: bool = False,
        link_state_enabled: bool = False,
    ) -> None:
        await self._client.configure_interface()
        await self._client.get_router().create_vpn_route()
        async with asyncio_util.run_async_context(
            self._client.events.wait_for_event_peer(
                public_key,
                [NodeState.CONNECTED],
                list(PathType),
                is_exit=True,
                is_vpn=True,
                timeout=timeout,
                link_state=LinkState.UP if link_state_enabled else None,
            )
        ) as event:
            self._client.get_runtime().allowed_pub_keys.add(public_key)

            if pq:
                await self._client.get_proxy().connect_to_exit_node_pq(
                    public_key=public_key,
                    allowed_ips=None,
                    endpoint=f"{ip}:{port}",
                )
            else:
                await self._client.get_proxy().connect_to_exit_node(
                    public_key=public_key,
                    allowed_ips=None,
                    endpoint=f"{ip}:{port}",
                )
            await event

    async def disconnect_from_vpn(
        self,
        public_key: str,
        timeout: Optional[float] = None,
    ) -> None:
        async with asyncio_util.run_async_context(
            self._client.events.wait_for_event_peer(
                public_key,
                [NodeState.DISCONNECTED],
                list(PathType),
                is_exit=True,
                is_vpn=True,
                timeout=timeout,
            )
        ) as event:
            await self._client.get_proxy().disconnect_from_exit_nodes()
            await asyncio.gather(
                event,
                self._client.get_router().delete_vpn_route(),
            )

    async def disconnect_from_exit_node(
        self,
        public_key: str,
        timeout: Optional[float] = None,
    ) -> None:
        async with asyncio_util.run_async_context(
            self._client.events.wait_for_event_peer(
                public_key, [NodeState.CONNECTED], list(PathType), timeout=timeout
            )
        ) as event:
            await self._client.get_proxy().disconnect_from_exit_nodes()
            await asyncio.gather(
                event,
                self._client.get_router().delete_vpn_route(),
            )

    async def connect_to_exit_node(
        self,
        public_key: str,
        timeout: Optional[float] = None,
    ) -> None:
        await self._client.configure_interface()
        await self._client.get_router().create_vpn_route()
        async with asyncio_util.run_async_context(
            self._client.events.wait_for_event_peer(
                public_key,
                [NodeState.CONNECTED],
                list(PathType),
                is_exit=True,
                timeout=timeout,
            )
        ) as event:
            await self._client.get_proxy().connect_to_exit_node(
                public_key=public_key, allowed_ips=None, endpoint=None
            )
            await event
