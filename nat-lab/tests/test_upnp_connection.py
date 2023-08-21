import asyncio
import pytest
from contextlib import AsyncExitStack
from mesh_api import API
from telio import AdapterType, State, PathType, Client
from telio_features import TelioFeatures, Direct
from utils import testing
from utils.connection_util import ConnectionTag, new_connection_with_gw
from utils.ping import Ping

ANY_PROVIDERS = ["local", "stun"]
LOCAL_PROVIDER = ["local"]
UPNP_PROVIDER = ["upnp"]


@pytest.mark.asyncio
@pytest.mark.derp
async def test_upnp_route_removed() -> None:
    async with AsyncExitStack() as exit_stack:
        api = API()

        (alpha, beta) = api.default_config_two_nodes()
        (alpha_connection, alpha_connection_gw) = await exit_stack.enter_async_context(
            new_connection_with_gw(ConnectionTag.DOCKER_UPNP_CLIENT_1)
        )
        (beta_connection, beta_connection_gw) = await exit_stack.enter_async_context(
            new_connection_with_gw(ConnectionTag.DOCKER_UPNP_CLIENT_2)
        )

        assert alpha_connection_gw
        assert beta_connection_gw

        await alpha_connection_gw.create_process(["upnpd", "eth0", "eth1"]).execute()
        await beta_connection_gw.create_process(["upnpd", "eth0", "eth1"]).execute()

        alpha_client = await exit_stack.enter_async_context(
            Client(
                alpha_connection,
                alpha,
                AdapterType.BoringTun,
                telio_features=TelioFeatures(direct=Direct(providers=UPNP_PROVIDER)),
            ).run_meshnet(
                api.get_meshmap(alpha.id),
            )
        )
        beta_client = await exit_stack.enter_async_context(
            Client(
                beta_connection,
                beta,
                AdapterType.BoringTun,
                telio_features=TelioFeatures(direct=Direct(providers=UPNP_PROVIDER)),
            ).run_meshnet(api.get_meshmap(beta.id))
        )

        await testing.wait_lengthy(
            asyncio.gather(
                alpha_client.wait_for_state_on_any_derp([State.Connected]),
                beta_client.wait_for_state_on_any_derp([State.Connected]),
                alpha_client.wait_for_state_peer(
                    beta.public_key, [State.Connected], [PathType.Direct]
                ),
                beta_client.wait_for_state_peer(
                    alpha.public_key, [State.Connected], [PathType.Direct]
                ),
            )
        )

        # Shutoff Upnpd on both gateways to wipe out all upnp created external
        # routes, this also requires to wipe-out the contrack list
        await alpha_connection_gw.create_process(["killall", "upnpd"]).execute()
        await beta_connection_gw.create_process(["killall", "upnpd"]).execute()
        await alpha_connection_gw.create_process(["conntrack", "-F"]).execute()
        await beta_connection_gw.create_process(["conntrack", "-F"]).execute()

        with pytest.raises(asyncio.TimeoutError):
            async with Ping(alpha_connection, beta.ip_addresses[0]).run() as ping:
                await testing.wait_long(ping.wait_for_next_ping())
        #  Turnon upnpd on both gateways, to enable creating new erternal routes
        await alpha_connection_gw.create_process(["upnpd", "eth0", "eth1"]).execute()
        await beta_connection_gw.create_process(["upnpd", "eth0", "eth1"]).execute()

        await testing.wait_lengthy(
            asyncio.gather(
                alpha_client.wait_for_event_peer(
                    beta.public_key, [State.Connected], [PathType.Direct]
                ),
                beta_client.wait_for_event_peer(
                    alpha.public_key, [State.Connected], [PathType.Direct]
                ),
            )
        )

        async with Ping(beta_connection, alpha.ip_addresses[0]).run() as ping:
            await testing.wait_lengthy(ping.wait_for_next_ping())
        async with Ping(alpha_connection, beta.ip_addresses[0]).run() as ping:
            await testing.wait_lengthy(ping.wait_for_next_ping())
