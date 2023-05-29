from utils import Ping
from contextlib import AsyncExitStack
from mesh_api import API
from telio import AdapterType, PathType
from utils import ConnectionTag, new_connection_by_tag, stun
import config
import pytest
import telio
import utils.testing as testing


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "alpha_connection_tag,adapter_type,public_ip",
    [
        pytest.param(
            ConnectionTag.DOCKER_CONE_CLIENT_1,
            AdapterType.BoringTun,
            "10.0.254.1",
        ),
        pytest.param(
            ConnectionTag.DOCKER_CONE_CLIENT_1,
            AdapterType.LinuxNativeWg,
            "10.0.254.1",
            marks=pytest.mark.linux_native,
        ),
        pytest.param(
            ConnectionTag.WINDOWS_VM,
            AdapterType.WindowsNativeWg,
            "10.0.254.7",
            marks=pytest.mark.windows,
        ),
        pytest.param(
            ConnectionTag.WINDOWS_VM,
            AdapterType.WireguardGo,
            "10.0.254.7",
            marks=pytest.mark.windows,
        ),
        # pytest.param(
        #     ConnectionTag.MAC_VM,
        #     AdapterType.Default,
        #     "10.0.254.7",
        #     marks=pytest.mark.mac,
        # ),
    ],
)
async def test_vpn_connection(
    alpha_connection_tag: ConnectionTag, adapter_type: AdapterType, public_ip: str
) -> None:
    async with AsyncExitStack() as exit_stack:
        api = API()

        alpha = api.register(
            name="alpha",
            id="96ddb926-4b86-11ec-81d3-0242ac130003",
            private_key="IAnPnSDobLEProbDcj0nKTroCyjr2w0Pr2nFa3z35Gg=",
            public_key="1eX7Fy78bokD5ZSNO5G11R+28v4xzawlsRdSJoU3jDg=",
        )
        api.assign_ip(alpha.id, "100.64.33.1")

        connection = await exit_stack.enter_async_context(
            new_connection_by_tag(alpha_connection_tag)
        )

        ip = await testing.wait_long(stun.get(connection, config.STUN_SERVER))
        assert ip == public_ip, f"wrong public IP before connecting to VPN {ip}"

        client_alpha = await exit_stack.enter_async_context(
            telio.run(
                connection,
                alpha,
                adapter_type,
            )
        )

        wg_server = config.WG_SERVER

        await testing.wait_long(
            client_alpha.connect_to_vpn(
                wg_server["ipv4"], wg_server["port"], wg_server["public_key"]
            )
        )

        await testing.wait_long(
            client_alpha.handshake(wg_server["public_key"], PathType.Direct)
        )

        async with Ping(connection, "10.0.80.80") as ping:
            await testing.wait_long(ping.wait_for_next_ping())

        ip = await testing.wait_long(stun.get(connection, config.STUN_SERVER))
        assert ip == wg_server["ipv4"], f"wrong public IP when connected to VPN {ip}"
