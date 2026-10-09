import asyncio
from tests.uniffi.telio_bindings import ConnectionConfig, VpnConnectionConfigBuilder
from tests.utils import asyncio_util
from tests.utils.bindings import LinkState, NodeState, PathType
from typing import Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from tests.libtelio_client.client import Client


class ClientVpn:
    def __init__(self, client: "Client") -> None:
        self._client = client

    async def connect(
        self,
        ip: str,
        port: int,
        public_key: str,
        timeout: Optional[float] = None,
        pq: bool = False,
        link_state_enabled: bool = False,
    ) -> None:
        builder = VpnConnectionConfigBuilder(public_key, f"{ip}:{port}")

        if pq:
            builder = builder.with_identifier("natlabpq").force_pq()
        else:
            builder = builder.with_identifier("natlab")

        await self.connect_with_config(
            builder.build(),
            timeout=timeout,
            link_state_enabled=link_state_enabled,
        )

    async def connect_with_config(
        self,
        config: ConnectionConfig,
        timeout: Optional[float] = None,
        link_state_enabled: bool = False,
    ) -> None:
        public_key = str(config.public_key)
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
            await self._client.get_proxy().connect_to_exit_node_with_config(config)
            await event

    async def disconnect(
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
