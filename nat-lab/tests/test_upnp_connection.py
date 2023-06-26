from utils import Ping
from contextlib import AsyncExitStack
from mesh_api import API
from utils import ConnectionTag, new_connection_with_gw, testing
from telio import PathType
from telio_features import TelioFeatures, Direct
import asyncio
import pytest
import telio
import time

ANY_PROVIDERS = ["local", "stun"]
LOCAL_PROVIDER = ["local"]
UPNP_PROVIDER = ["upnp"]


@pytest.mark.asyncio
async def test_upnp_route_corrupted() -> None:
    async with AsyncExitStack() as exit_stack:
        CLIENT_ALPHA_IP = "100.72.31.21"
        CLIENT_BETA_IP = "100.72.31.22"

        api = API()
        alpha = api.register(
            name="alpha",
            id="96ddb926-4b86-11ec-81d3-0242ac130003",
            private_key="mODRJKABR4wDCjXn899QO6wb83azXKZF7hcfX8dWuUA=",
            public_key="3XCOtCGl5tZJ8N5LksxkjfeqocW0BH2qmARD7qzHDkI=",
        )
        beta = api.register(
            name="beta",
            id="7b4548ca-fe5a-4597-8513-896f38c6d6ae",
            private_key="GN+D2Iy9p3UmyBZhgxU4AhbLT6sxY0SUhXu0a0TuiV4=",
            public_key="UnB+btGMEBXcR7EchMi28Hqk0Q142WokO6n313dt3mc=",
        )
        api.assign_ip(alpha.id, CLIENT_ALPHA_IP)
        api.assign_ip(beta.id, CLIENT_BETA_IP)

        # create a rule in  iptables to accept connections
        beta.set_peer_firewall_settings(alpha.id, allow_incoming_connections=True)
        alpha.set_peer_firewall_settings(beta.id, allow_incoming_connections=True)

        (alpha_connection, alpha_connection_gw) = await exit_stack.enter_async_context(
            new_connection_with_gw(ConnectionTag.DOCKER_UPNP_CLIENT_1)
        )

        (beta_connection, beta_connection_gw) = await exit_stack.enter_async_context(
            new_connection_with_gw(ConnectionTag.DOCKER_UPNP_CLIENT_2)
        )

        if alpha_connection_gw:
            await alpha_connection_gw.create_process(
                ["upnpd", "eth0", "eth1"]
            ).execute()
        if beta_connection_gw:
            await beta_connection_gw.create_process(["upnpd", "eth0", "eth1"]).execute()
        alpha_client = await exit_stack.enter_async_context(
            telio.run_meshnet(
                alpha_connection,
                alpha,
                api.get_meshmap(alpha.id),
                telio.AdapterType.BoringTun,
                telio_features=TelioFeatures(direct=Direct(providers=UPNP_PROVIDER)),
            )
        )

        beta_client = await exit_stack.enter_async_context(
            telio.run_meshnet(
                beta_connection,
                beta,
                api.get_meshmap(beta.id),
                telio.AdapterType.BoringTun,
                telio_features=TelioFeatures(direct=Direct(providers=UPNP_PROVIDER)),
            )
        )

        await testing.wait_lengthy(
            alpha_client.wait_for_any_derp_state([telio.State.Connected])
        )
        await testing.wait_lengthy(
            beta_client.wait_for_any_derp_state([telio.State.Connected])
        )

        await testing.wait_lengthy(
            alpha_client.handshake(
                beta.public_key,
                PathType.Direct,
            ),
        )
        await testing.wait_lengthy(
            beta_client.handshake(
                alpha.public_key,
                PathType.Direct,
            )
        )

        # Reset Upnpd on both gateways
        # this also requires to wipe-out the contrack list
        if alpha_connection_gw and beta_connection_gw:
            await alpha_connection_gw.create_process(["killall", "upnpd"]).execute()
            await beta_connection_gw.create_process(["killall", "upnpd"]).execute()
            await alpha_connection_gw.create_process(["conntrack", "-F"]).execute()
            await beta_connection_gw.create_process(["conntrack", "-F"]).execute()
            await alpha_connection_gw.create_process(
                ["upnpd", "eth0", "eth1"]
            ).execute()
            await beta_connection_gw.create_process(["upnpd", "eth0", "eth1"]).execute()

        with pytest.raises(asyncio.TimeoutError):
            async with Ping(alpha_connection, CLIENT_BETA_IP) as ping:
                await testing.wait_long(ping.wait_for_next_ping())

        await testing.wait_lengthy(
            alpha_client.handshake(
                beta.public_key,
                PathType.Direct,
            ),
        )
        await testing.wait_lengthy(
            beta_client.handshake(
                alpha.public_key,
                PathType.Direct,
            )
        )

        time.sleep(10)
        async with Ping(beta_connection, CLIENT_ALPHA_IP) as ping:
            await testing.wait_long(ping.wait_for_next_ping())

        async with Ping(alpha_connection, CLIENT_BETA_IP) as ping:
            await testing.wait_long(ping.wait_for_next_ping())
