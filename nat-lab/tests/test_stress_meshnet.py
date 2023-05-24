from utils import Ping
from contextlib import AsyncExitStack
from mesh_api import API
from telio import AdapterType, PathType
from utils import ConnectionTag, new_connection_by_tag
from utils.iperf3 import IperfClient, IperfServer, Protocol
import asyncio
import pytest
import telio
import utils.testing as testing
import config


@pytest.mark.asyncio
@pytest.mark.timeout(180 + 60)
@pytest.mark.long
@pytest.mark.skip(reason="used only for debugging locally")
@pytest.mark.parametrize("sync", [True, False])
@pytest.mark.parametrize("send", [True, False])
@pytest.mark.parametrize(
    "alpha_connection_tag,alpha_ip_addr",
    [
        pytest.param(
            ConnectionTag.DOCKER_SHARED_CLIENT_1,
            "192.168.102.67",
        ),
        pytest.param(
            ConnectionTag.WINDOWS_VM,
            config.WINDOWS_VM_IP,
            marks=pytest.mark.windows,
        ),
        pytest.param(
            ConnectionTag.MAC_VM,
            config.MAC_VM_IP,
            marks=pytest.mark.mac,
        ),
    ],
)
async def test_speed(
    alpha_connection_tag: ConnectionTag,
    alpha_ip_addr: str,
    sync: bool,
    send: bool,
) -> None:
    async with AsyncExitStack() as exit_stack:
        connection_alpha = await exit_stack.enter_async_context(
            new_connection_by_tag(alpha_connection_tag)
        )
        connection_beta = await exit_stack.enter_async_context(
            new_connection_by_tag(ConnectionTag.DOCKER_CONE_CLIENT_2)
        )

        async with Ping(connection_alpha, config.DOCKER_CONE_CLIENT_2_LAN_ADDR) as ping:
            await testing.wait_long(ping.wait_for_next_ping())
        async with Ping(connection_beta, alpha_ip_addr) as ping:
            await testing.wait_long(ping.wait_for_next_ping())

        alpha_server = IperfServer(connection_alpha, "ALPHA", False, Protocol.Tcp)
        beta_server = IperfServer(connection_beta, "BETA", False, Protocol.Tcp)

        await exit_stack.enter_async_context(alpha_server)
        await exit_stack.enter_async_context(beta_server)

        alpha_client = IperfClient(
            config.DOCKER_CONE_CLIENT_2_LAN_ADDR,
            connection_alpha,
            "ALPHA",
            10,
            1024,
            False,
            Protocol.Tcp,
            send,
        )
        beta_client = IperfClient(
            alpha_ip_addr, connection_beta, "BETA", 10, 1024, False, Protocol.Tcp, send
        )

        if sync:
            await exit_stack.enter_async_context(alpha_client)
            await asyncio.wait_for(
                asyncio.gather(
                    beta_server.listening_started(),
                    alpha_client.done(),
                ),
                120,
            )
            await exit_stack.enter_async_context(beta_client)
            await asyncio.wait_for(
                asyncio.gather(
                    alpha_server.listening_started(),
                    beta_client.done(),
                ),
                120,
            )
        else:
            await exit_stack.enter_async_context(alpha_client)
            await exit_stack.enter_async_context(beta_client)
            await asyncio.wait_for(
                asyncio.gather(
                    alpha_server.listening_started(),
                    beta_server.listening_started(),
                    alpha_client.done(),
                    beta_client.done(),
                ),
                120,
            )

        speed_type = str("download" if send == False else "upload")
        send_mode = str("unidirectional" if sync == True else "bidirectional")

        print(
            f"[DEBUG] [alpha] {connection_alpha.target_os} - {speed_type} speed {alpha_client.get_speed() / 1000} Mbits/sec in {send_mode} mode"
        )
        print(
            f"[DEBUG] [beta] {connection_beta.target_os} - {speed_type} speed {beta_client.get_speed() / 1000} Mbits/sec in {send_mode} mode"
        )


@pytest.mark.asyncio
@pytest.mark.timeout(180 + 60)
@pytest.mark.long
@pytest.mark.skip(reason="used only for debugging locally")
@pytest.mark.parametrize("sync", [True, False])
@pytest.mark.parametrize("send", [True, False])
@pytest.mark.parametrize("path_type", [PathType.Relay, PathType.Direct])
@pytest.mark.parametrize(
    "alpha_connection_tag,beta_connection_tag,alpha_adapter_type,beta_adapter_type",
    [
        pytest.param(
            ConnectionTag.DOCKER_CONE_CLIENT_1,
            ConnectionTag.DOCKER_CONE_CLIENT_2,
            AdapterType.BoringTun,
            AdapterType.BoringTun,
        ),
        pytest.param(
            ConnectionTag.DOCKER_CONE_CLIENT_1,
            ConnectionTag.DOCKER_CONE_CLIENT_2,
            AdapterType.LinuxNativeWg,
            AdapterType.LinuxNativeWg,
            marks=pytest.mark.linux_native,
        ),
        pytest.param(
            ConnectionTag.DOCKER_CONE_CLIENT_1,
            ConnectionTag.DOCKER_CONE_CLIENT_2,
            AdapterType.BoringTun,
            AdapterType.LinuxNativeWg,
            marks=pytest.mark.linux_native,
        ),
        pytest.param(
            ConnectionTag.DOCKER_CONE_CLIENT_1,
            ConnectionTag.WINDOWS_VM,
            AdapterType.BoringTun,
            AdapterType.WindowsNativeWg,
            marks=pytest.mark.windows,
        ),
        pytest.param(
            ConnectionTag.DOCKER_CONE_CLIENT_1,
            ConnectionTag.WINDOWS_VM,
            AdapterType.BoringTun,
            AdapterType.WireguardGo,
            marks=pytest.mark.windows,
        ),
        pytest.param(
            ConnectionTag.DOCKER_CONE_CLIENT_1,
            ConnectionTag.WINDOWS_VM,
            AdapterType.LinuxNativeWg,
            AdapterType.WindowsNativeWg,
            marks=[pytest.mark.windows, pytest.mark.linux_native],
        ),
        pytest.param(
            ConnectionTag.DOCKER_CONE_CLIENT_1,
            ConnectionTag.WINDOWS_VM,
            AdapterType.LinuxNativeWg,
            AdapterType.WireguardGo,
            marks=[pytest.mark.windows, pytest.mark.linux_native],
        ),
        pytest.param(
            ConnectionTag.DOCKER_CONE_CLIENT_1,
            ConnectionTag.MAC_VM,
            AdapterType.BoringTun,
            AdapterType.Default,
            marks=pytest.mark.mac,
        ),
        pytest.param(
            ConnectionTag.DOCKER_CONE_CLIENT_1,
            ConnectionTag.MAC_VM,
            AdapterType.LinuxNativeWg,
            AdapterType.Default,
            marks=[pytest.mark.mac, pytest.mark.linux_native],
        ),
        pytest.param(
            ConnectionTag.WINDOWS_VM,
            ConnectionTag.MAC_VM,
            AdapterType.WindowsNativeWg,
            AdapterType.Default,
            marks=[pytest.mark.mac, pytest.mark.windows],
        ),
        pytest.param(
            ConnectionTag.WINDOWS_VM,
            ConnectionTag.MAC_VM,
            AdapterType.WireguardGo,
            AdapterType.Default,
            marks=[pytest.mark.mac, pytest.mark.windows],
        ),
    ],
)
async def test_meshnet_speed(
    alpha_connection_tag: ConnectionTag,
    beta_connection_tag: ConnectionTag,
    alpha_adapter_type: AdapterType,
    beta_adapter_type: AdapterType,
    path_type: str,
    send: bool,
    sync: bool,
) -> None:
    async with AsyncExitStack() as exit_stack:
        api = API()
        ALPHA_IP = "100.64.0.1"
        BETA_IP = "100.64.0.2"

        alpha = api.register(
            name="alpha",
            id="96ddb926-4b86-11ec-81d3-0242ac130003",
            private_key="IGm+42FLMMGZRaQvk6F3UPbl+T/CBk8W+NPoX2/AdlU=",
            public_key="41CCEssnYIh8/8D8YvbTfWEcFanG3D0I0z1tRcN1Lyc=",
        )

        beta = api.register(
            name="beta",
            id="7b4548ca-fe5a-4597-8513-896f38c6d6ae",
            private_key="SPFD84gPtBNc3iGY9Cdrj+mSCwBeh3mCMWfPaeWQolw=",
            public_key="Q1M3VKUcfTmGsrRzY6BpNds1yDIUvPVcs/2TySv/t1U=",
        )

        api.assign_ip(alpha.id, ALPHA_IP)
        api.assign_ip(beta.id, BETA_IP)

        alpha.set_peer_firewall_settings(beta.id, allow_incoming_connections=True)
        beta.set_peer_firewall_settings(alpha.id, allow_incoming_connections=True)

        connection_alpha = await exit_stack.enter_async_context(
            new_connection_by_tag(alpha_connection_tag)
        )
        connection_beta = await exit_stack.enter_async_context(
            new_connection_by_tag(beta_connection_tag)
        )

        client_alpha = await exit_stack.enter_async_context(
            telio.run_meshnet(
                connection_alpha,
                alpha,
                api.get_meshmap(alpha.id),
                alpha_adapter_type,
                path_type,
            )
        )

        client_beta = await exit_stack.enter_async_context(
            telio.run_meshnet(
                connection_beta,
                beta,
                api.get_meshmap(beta.id),
                beta_adapter_type,
                path_type,
            )
        )

        await testing.wait_defined(
            asyncio.gather(
                client_alpha.handshake(beta.public_key, path_type),
                client_beta.handshake(alpha.public_key, path_type),
            ),
            80 if path_type == PathType.Direct else 5,
        )

        async with Ping(connection_alpha, BETA_IP) as ping:
            await testing.wait_long(ping.wait_for_next_ping())
        async with Ping(connection_beta, ALPHA_IP) as ping:
            await testing.wait_long(ping.wait_for_next_ping())

        alpha_server = IperfServer(connection_alpha, alpha.name, False, Protocol.Tcp)
        beta_server = IperfServer(connection_beta, beta.name, False, Protocol.Tcp)

        await exit_stack.enter_async_context(alpha_server)
        await exit_stack.enter_async_context(beta_server)

        alpha_client = IperfClient(
            BETA_IP, connection_alpha, alpha.name, 10, 1024, False, Protocol.Tcp, send
        )
        beta_client = IperfClient(
            ALPHA_IP, connection_beta, beta.name, 10, 1024, False, Protocol.Tcp, send
        )

        if sync:
            await exit_stack.enter_async_context(alpha_client)
            await asyncio.wait_for(
                asyncio.gather(
                    beta_server.listening_started(),
                    alpha_client.done(),
                ),
                120,
            )
            await exit_stack.enter_async_context(beta_client)
            await asyncio.wait_for(
                asyncio.gather(
                    alpha_server.listening_started(),
                    beta_client.done(),
                ),
                120,
            )
        else:
            await exit_stack.enter_async_context(alpha_client)
            await exit_stack.enter_async_context(beta_client)
            await asyncio.wait_for(
                asyncio.gather(
                    alpha_server.listening_started(),
                    beta_server.listening_started(),
                    alpha_client.done(),
                    beta_client.done(),
                ),
                120,
            )

        speed_type = str("download" if send == False else "upload")
        send_mode = str("unidirectional" if sync == True else "bidirectional")

        print(
            f"[DEBUG] [alpha] {connection_alpha.target_os} - {speed_type} speed {alpha_client.get_speed() / 1000} Mbits/sec in {send_mode} mode via {path_type}"
        )
        print(
            f"[DEBUG] [beta] {connection_beta.target_os} - {speed_type} speed {beta_client.get_speed() / 1000} Mbits/sec in {send_mode} mode via {path_type}"
        )

        async with Ping(connection_alpha, BETA_IP) as ping:
            await testing.wait_long(ping.wait_for_next_ping())
        async with Ping(connection_beta, ALPHA_IP) as ping:
            await testing.wait_long(ping.wait_for_next_ping())
