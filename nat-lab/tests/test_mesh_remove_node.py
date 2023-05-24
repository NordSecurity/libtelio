from utils import Ping
from contextlib import AsyncExitStack
from mesh_api import API
from telio import AdapterType
from utils import ConnectionTag, new_connection_by_tag
import asyncio
import pytest
import telio
import utils.testing as testing


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "alpha_connection_tag,adapter_type",
    [
        pytest.param(
            ConnectionTag.DOCKER_CONE_CLIENT_1,
            AdapterType.BoringTun,
        ),
        pytest.param(
            ConnectionTag.DOCKER_CONE_CLIENT_1,
            AdapterType.LinuxNativeWg,
            marks=pytest.mark.linux_native,
        ),
        pytest.param(
            ConnectionTag.WINDOWS_VM,
            AdapterType.WindowsNativeWg,
            marks=pytest.mark.windows,
        ),
        pytest.param(
            ConnectionTag.WINDOWS_VM,
            AdapterType.WireguardGo,
            marks=pytest.mark.windows,
        ),
        pytest.param(
            ConnectionTag.MAC_VM,
            AdapterType.Default,
            marks=pytest.mark.mac,
        ),
    ],
)
async def test_mesh_remove_node(
    alpha_connection_tag: ConnectionTag, adapter_type: AdapterType
) -> None:
    async with AsyncExitStack() as exit_stack:
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

        gamma = api.register(
            name="gamma",
            id="39388b1e-ebd8-11ec-8ea0-0242ac120002",
            private_key="wAraYW+DNmY/7zr0whsGCscrGCKToR6gq9XiqlJziWE=",
            public_key="AqS9/TMs5+Cb2Al72UYRlwS6XsYlte7rAt/uiNBQfTs=",
        )

        api.assign_ip(alpha.id, "100.64.0.1")
        api.assign_ip(beta.id, "100.64.0.2")
        api.assign_ip(gamma.id, "100.64.0.3")

        beta.set_peer_firewall_settings(alpha.id, allow_incoming_connections=True)
        gamma.set_peer_firewall_settings(beta.id, allow_incoming_connections=True)
        alpha.set_peer_firewall_settings(gamma.id, allow_incoming_connections=True)

        connection_alpha = await exit_stack.enter_async_context(
            new_connection_by_tag(alpha_connection_tag)
        )
        connection_beta = await exit_stack.enter_async_context(
            new_connection_by_tag(ConnectionTag.DOCKER_CONE_CLIENT_2)
        )
        connection_gamma = await exit_stack.enter_async_context(
            new_connection_by_tag(ConnectionTag.DOCKER_SYMMETRIC_CLIENT_1)
        )

        client_alpha = await exit_stack.enter_async_context(
            telio.run_meshnet(
                connection_alpha,
                alpha,
                api.get_meshmap(alpha.id),
                adapter_type,
            )
        )

        client_beta = await exit_stack.enter_async_context(
            telio.run_meshnet(
                connection_beta,
                beta,
                api.get_meshmap(beta.id),
            )
        )

        client_gamma = await exit_stack.enter_async_context(
            telio.run_meshnet(
                connection_gamma,
                gamma,
                api.get_meshmap(gamma.id),
            )
        )

        await testing.wait_long(client_alpha.handshake(beta.public_key))
        await testing.wait_long(client_beta.handshake(alpha.public_key))
        await testing.wait_long(client_alpha.handshake(gamma.public_key))
        await testing.wait_long(client_gamma.handshake(alpha.public_key))
        await testing.wait_long(client_gamma.handshake(beta.public_key))
        await testing.wait_long(client_beta.handshake(gamma.public_key))

        async with Ping(connection_alpha, "100.64.0.2") as ping:
            await testing.wait_long(ping.wait_for_next_ping())
        async with Ping(connection_beta, "100.64.0.3") as ping:
            await testing.wait_long(ping.wait_for_next_ping())
        async with Ping(connection_gamma, "100.64.0.1") as ping:
            await testing.wait_long(ping.wait_for_next_ping())

        api.remove(gamma.id)

        await client_alpha.set_meshmap(api.get_meshmap(alpha.id))
        await client_beta.set_meshmap(api.get_meshmap(beta.id))

        async with Ping(connection_alpha, "100.64.0.2") as ping:
            await testing.wait_long(ping.wait_for_next_ping())

        with pytest.raises(asyncio.TimeoutError):
            async with Ping(connection_beta, "100.64.0.3") as ping:
                await testing.wait_normal(ping.wait_for_next_ping())

        with pytest.raises(asyncio.TimeoutError):
            async with Ping(connection_gamma, "100.64.0.1") as ping:
                await testing.wait_normal(ping.wait_for_next_ping())
