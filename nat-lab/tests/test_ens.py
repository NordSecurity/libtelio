import aiohttp
import asyncio
import base64
import config
import pytest
from contextlib import AsyncExitStack
from helpers import SetupParameters, setup_api, setup_environment, setup_connections
from helpers_vpn import connect_vpn, VpnConfig
from typing import cast
from utils import stun
from utils.bindings import (
    default_features,
    PathType,
    NodeState,
    RelayState,
    TelioAdapterType,
    VpnConnectionError,
)
from utils.connection import ConnectionTag
from utils.connection_util import generate_connection_tracker_config
from utils.ping import ping
from utils.router import IPProto, IPStack

ENS_PORT = 993
ENS_LOG_STR = "Will start ENS monitoring"


@pytest.mark.parametrize(
    "alpha_setup_params",
    [
        pytest.param(
            SetupParameters(
                connection_tag=ConnectionTag.DOCKER_CONE_CLIENT_1,
                adapter_type_override=TelioAdapterType.NEP_TUN,
                connection_tracker_config=generate_connection_tracker_config(
                    ConnectionTag.DOCKER_CONE_CLIENT_1,
                    nlx_1_limits=(0, 0),
                    derp_1_limits=(1, 1),
                ),
                features=default_features(
                    enable_error_notification_service=True,
                    enable_direct=True,
                ),
            )
        ),
        pytest.param(
            SetupParameters(
                connection_tag=ConnectionTag.VM_WINDOWS_1,
                adapter_type_override=TelioAdapterType.WINDOWS_NATIVE_TUN,
                connection_tracker_config=generate_connection_tracker_config(
                    ConnectionTag.VM_WINDOWS_1,
                    nlx_1_limits=(0, 0),
                    derp_1_limits=(1, 1),
                ),
                features=default_features(
                    enable_error_notification_service=True,
                    enable_direct=True,
                ),
            ),
            marks=pytest.mark.windows,
        ),
        pytest.param(
            SetupParameters(
                connection_tag=ConnectionTag.VM_MAC,
                adapter_type_override=TelioAdapterType.NEP_TUN,
                connection_tracker_config=generate_connection_tracker_config(
                    ConnectionTag.VM_MAC,
                    nlx_1_limits=(0, 0),
                    derp_1_limits=(1, 1),
                ),
                features=default_features(
                    enable_error_notification_service=True,
                    enable_direct=True,
                ),
            ),
            marks=pytest.mark.mac,
        ),
    ],
)
@pytest.mark.parametrize(
    "beta_setup_params",
    [
        pytest.param(
            SetupParameters(
                connection_tag=ConnectionTag.DOCKER_CONE_CLIENT_2,
                connection_tracker_config=generate_connection_tracker_config(
                    ConnectionTag.DOCKER_CONE_CLIENT_2,
                    nlx_1_limits=(0, 0),
                    derp_1_limits=(1, 1),
                ),
                features=default_features(
                    enable_error_notification_service=True,
                    enable_direct=True,
                    enable_firewall_exclusion_range="10.0.0.0/8",
                ),
            )
        )
    ],
)
async def test_ens_not_started_for_meshnet_exit_peer(
    alpha_setup_params: SetupParameters,
    beta_setup_params: SetupParameters,
) -> None:
    async with AsyncExitStack() as exit_stack:
        api, (alpha, beta) = setup_api([(False, IPStack.IPv4), (False, IPStack.IPv4)])
        beta.set_peer_firewall_settings(
            alpha.id,
            allow_incoming_connections=True,
            allow_peer_traffic_routing=True,
        )

        env = await exit_stack.enter_async_context(
            setup_environment(exit_stack, [alpha_setup_params, beta_setup_params], api)
        )

        client_alpha, client_beta = env.clients
        connection_alpha, _ = [conn.connection for conn in env.connections]

        await asyncio.gather(
            client_alpha.wait_for_state_on_any_derp([RelayState.CONNECTED]),
            client_beta.wait_for_state_on_any_derp([RelayState.CONNECTED]),
        )

        await client_alpha.set_meshnet_config(api.get_meshnet_config(alpha.id))
        await client_beta.set_meshnet_config(api.get_meshnet_config(beta.id))

        await asyncio.gather(
            client_alpha.wait_for_state_peer(
                beta.public_key, [NodeState.CONNECTED], [PathType.DIRECT]
            ),
            client_beta.wait_for_state_peer(
                alpha.public_key, [NodeState.CONNECTED], [PathType.DIRECT]
            ),
        )

        await ping(connection_alpha, cast(str, beta.get_ip_address(IPProto.IPv4)))
        await client_beta.get_router().create_exit_node_route()

        logs_before = await client_alpha.get_log()
        ens_starts_before = logs_before.count(ENS_LOG_STR)

        await client_alpha.connect_to_exit_node(beta.public_key)
        await client_alpha.wait_for_state_peer(
            beta.public_key,
            [NodeState.CONNECTED],
            list(PathType),
            is_exit=True,
            is_vpn=False,
        )

        logs_after = await client_alpha.get_log()
        assert (
            logs_after.count(ENS_LOG_STR) == ens_starts_before == 0
        ), "ENS started while routing through a meshnet peer"


@pytest.mark.parametrize(
    "alpha_setup_params, public_ip",
    [
        pytest.param(
            SetupParameters(
                connection_tag=ConnectionTag.DOCKER_CONE_CLIENT_1,
                adapter_type_override=TelioAdapterType.NEP_TUN,
                is_meshnet=False,
                features=default_features(
                    enable_error_notification_service=True,
                ),
            ),
            "10.0.254.1",
        ),
        pytest.param(
            SetupParameters(
                connection_tag=ConnectionTag.VM_WINDOWS_1,
                adapter_type_override=TelioAdapterType.WINDOWS_NATIVE_TUN,
                is_meshnet=False,
                features=default_features(
                    enable_error_notification_service=True,
                ),
            ),
            "10.0.254.15",
            marks=[
                pytest.mark.windows,
            ],
        ),
        pytest.param(
            SetupParameters(
                connection_tag=ConnectionTag.VM_MAC,
                adapter_type_override=TelioAdapterType.NEP_TUN,
                is_meshnet=False,
                features=default_features(
                    enable_error_notification_service=True,
                ),
            ),
            "10.0.254.19",
            marks=pytest.mark.mac,
        ),
    ],
)
@pytest.mark.parametrize(
    "error_code",
    [
        VpnConnectionError.UNKNOWN,
        VpnConnectionError.CONNECTION_LIMIT_REACHED,
        VpnConnectionError.SERVER_MAINTENANCE,
        VpnConnectionError.UNAUTHENTICATED,
        VpnConnectionError.SUPERSEDED,
        VpnConnectionError.UNKNOWN,
    ],
)
async def test_ens(
    alpha_setup_params: SetupParameters,
    public_ip: str,
    error_code: VpnConnectionError,
) -> None:
    vpn_conf = VpnConfig(config.WG_SERVER, ConnectionTag.DOCKER_VPN_1, True)
    fingerprint = await get_grpc_tls_fingerprint(vpn_conf.server_conf["ipv4"])
    root_certificate = await get_grpc_tls_root_certificate(vpn_conf.server_conf["ipv4"])
    root_certificate = base64.b64decode(root_certificate)

    async with AsyncExitStack() as exit_stack:

        await set_vpn_server_private_key(
            vpn_conf.server_conf["ipv4"],
            vpn_conf.server_conf["private_key"],
        )

        alpha_setup_params.connection_tracker_config = (
            generate_connection_tracker_config(
                alpha_setup_params.connection_tag,
                stun_limits=(1, 1),
                vpn_1_limits=(
                    (1, 1)
                    if vpn_conf.conn_tag == ConnectionTag.DOCKER_VPN_1
                    else (0, 0)
                ),
            )
        )
        assert alpha_setup_params.features.error_notification_service
        alpha_setup_params.features.error_notification_service.allow_only_pq = False
        alpha_setup_params.features.error_notification_service.root_certificate_override = (
            root_certificate
        )
        env = await exit_stack.enter_async_context(
            setup_environment(exit_stack, [alpha_setup_params], prepare_vpn=True)
        )

        client_conn, *_ = [conn.connection for conn in env.connections]
        client_alpha, *_ = env.clients

        ip = await stun.get(client_conn, config.STUN_SERVER)
        assert ip == public_ip, f"wrong public IP before connecting to VPN {ip}"

        await setup_connections(exit_stack, [vpn_conf.conn_tag])

        await client_alpha.connect_to_vpn(
            cast(str, vpn_conf.server_conf["ipv4"]),
            cast(int, vpn_conf.server_conf["port"]),
            cast(str, vpn_conf.server_conf["public_key"]),
        )

        additional_info = "some additional info"
        await trigger_connection_error(
            vpn_conf.server_conf["ipv4"], error_code.value, additional_info
        )
        await client_alpha.wait_for_state_peer(
            vpn_conf.server_conf["public_key"],
            [NodeState.CONNECTED],
            [PathType.DIRECT],
            True,
            True,
            vpn_connection_error=error_code,
        )
        await client_alpha.wait_for_log(additional_info)
        await client_alpha.wait_for_log(fingerprint)


@pytest.mark.parametrize(
    "alpha_setup_params, public_ip",
    [
        pytest.param(
            SetupParameters(
                connection_tag=ConnectionTag.DOCKER_CONE_CLIENT_1,
                adapter_type_override=TelioAdapterType.NEP_TUN,
                is_meshnet=False,
                features=default_features(
                    enable_error_notification_service=True,
                ),
            ),
            "10.0.254.1",
        ),
        pytest.param(
            SetupParameters(
                connection_tag=ConnectionTag.VM_WINDOWS_1,
                adapter_type_override=TelioAdapterType.WINDOWS_NATIVE_TUN,
                is_meshnet=False,
                features=default_features(
                    enable_error_notification_service=True,
                ),
            ),
            "10.0.254.15",
            marks=[
                pytest.mark.windows,
            ],
        ),
        pytest.param(
            SetupParameters(
                connection_tag=ConnectionTag.VM_MAC,
                adapter_type_override=TelioAdapterType.NEP_TUN,
                is_meshnet=False,
                features=default_features(
                    enable_error_notification_service=True,
                ),
            ),
            "10.0.254.19",
            marks=pytest.mark.mac,
        ),
    ],
)
async def test_ens_will_not_emit_errors_from_incorrect_tls_session(
    alpha_setup_params: SetupParameters,
    public_ip: str,
) -> None:
    vpn_conf = VpnConfig(config.WG_SERVER, ConnectionTag.DOCKER_VPN_1, True)
    fingerprint = await get_grpc_tls_fingerprint(vpn_conf.server_conf["ipv4"])
    root_certificate = await get_grpc_tls_root_certificate(
        vpn_conf.server_conf["ipv4"], incorrect=True
    )
    root_certificate = base64.b64decode(root_certificate)
    error_code = VpnConnectionError.UNKNOWN

    async with AsyncExitStack() as exit_stack:

        await set_vpn_server_private_key(
            vpn_conf.server_conf["ipv4"],
            vpn_conf.server_conf["private_key"],
        )

        alpha_setup_params.connection_tracker_config = (
            generate_connection_tracker_config(
                alpha_setup_params.connection_tag,
                stun_limits=(1, 1),
                vpn_1_limits=(
                    (1, 1)
                    if vpn_conf.conn_tag == ConnectionTag.DOCKER_VPN_1
                    else (0, 0)
                ),
            )
        )
        assert alpha_setup_params.features.error_notification_service
        alpha_setup_params.features.error_notification_service.allow_only_pq = False
        alpha_setup_params.features.error_notification_service.root_certificate_override = (
            root_certificate
        )
        env = await exit_stack.enter_async_context(
            setup_environment(exit_stack, [alpha_setup_params], prepare_vpn=True)
        )

        client_conn, *_ = [conn.connection for conn in env.connections]
        client_alpha, *_ = env.clients

        ip = await stun.get(client_conn, config.STUN_SERVER)
        assert ip == public_ip, f"wrong public IP before connecting to VPN {ip}"

        await setup_connections(exit_stack, [vpn_conf.conn_tag])

        await client_alpha.connect_to_vpn(
            cast(str, vpn_conf.server_conf["ipv4"]),
            cast(int, vpn_conf.server_conf["port"]),
            cast(str, vpn_conf.server_conf["public_key"]),
        )

        additional_info = "some additional info"
        await trigger_connection_error(
            vpn_conf.server_conf["ipv4"], error_code.value, additional_info
        )

        with pytest.raises(asyncio.TimeoutError):
            await client_alpha.wait_for_state_peer(
                vpn_conf.server_conf["public_key"],
                [NodeState.CONNECTED],
                [PathType.DIRECT],
                True,
                True,
                timeout=15,
                vpn_connection_error=error_code,
            )

        with pytest.raises(asyncio.TimeoutError):
            async with asyncio.timeout(5):
                await client_alpha.wait_for_log(additional_info)
        await client_alpha.wait_for_log(fingerprint)
        await client_alpha.wait_for_log("InvalidCertificate(UnknownIssuer)")


async def trigger_connection_error(vpn_ip, error_code, additional_info):
    data = {"code": error_code, "additional_info": additional_info}
    url = f"http://{vpn_ip}:8000/api/connection_error"
    await make_post(url, data)


async def set_vpn_server_private_key(vpn_ip, vpn_server_private_key):
    data = {"vpn_server_private_key": vpn_server_private_key}
    url = f"http://{vpn_ip}:8000/api/vpn_server_private_key"
    await make_post(url, data)


async def make_post(url, data):
    async with aiohttp.ClientSession() as session:
        async with session.post(url, json=data) as response:
            if response.status == 200:
                json = await response.json()
                return json
            print(f"Error posting to {url}: Status {response.status}")
            return None


async def get_grpc_tls_fingerprint(vpn_ip):
    url = f"http://{vpn_ip}:8000/api/grpc_tls_fingerprint"
    json = await make_get_json(url)
    return json["fingerprint"]


async def get_grpc_tls_root_certificate(vpn_ip, incorrect=False):
    if incorrect:
        url = f"http://{vpn_ip}:8000/api/incorrect_root_certificate"
    else:
        url = f"http://{vpn_ip}:8000/api/grpc_tls_root_certificate"

    json = await make_get_json(url)
    return json["root_certificate"]


async def make_get_json(url):
    async with aiohttp.ClientSession() as session:
        async with session.get(url) as response:
            if response.status == 200:
                json = await response.json()
                return json
            print(f"Error fetching {url}: Status {response.status}")
            return None


@pytest.mark.parametrize(
    "alpha_setup_params, public_ip",
    [
        pytest.param(
            SetupParameters(
                connection_tag=ConnectionTag.DOCKER_CONE_CLIENT_1,
                adapter_type_override=TelioAdapterType.NEP_TUN,
                is_meshnet=False,
                features=default_features(
                    enable_error_notification_service=True,
                ),
            ),
            "10.0.254.1",
        ),
        pytest.param(
            SetupParameters(
                connection_tag=ConnectionTag.VM_WINDOWS_1,
                adapter_type_override=TelioAdapterType.WINDOWS_NATIVE_TUN,
                is_meshnet=False,
                features=default_features(
                    enable_error_notification_service=True,
                ),
            ),
            "10.0.254.15",
            marks=[
                pytest.mark.windows,
            ],
        ),
        pytest.param(
            SetupParameters(
                connection_tag=ConnectionTag.VM_MAC,
                adapter_type_override=TelioAdapterType.NEP_TUN,
                is_meshnet=False,
                features=default_features(
                    enable_error_notification_service=True,
                ),
            ),
            "10.0.254.19",
            marks=pytest.mark.mac,
        ),
    ],
)
async def test_ens_not_working(
    alpha_setup_params: SetupParameters,
    public_ip: str,
) -> None:
    vpn_conf = VpnConfig(config.WG_SERVER, ConnectionTag.DOCKER_VPN_1, True)
    async with AsyncExitStack() as exit_stack:
        await set_vpn_server_private_key(
            vpn_conf.server_conf["ipv4"],
            vpn_conf.server_conf["private_key"],
        )

        alpha_setup_params.connection_tracker_config = (
            generate_connection_tracker_config(
                alpha_setup_params.connection_tag,
                stun_limits=(1, 1),
                vpn_1_limits=(
                    (1, 1)
                    if vpn_conf.conn_tag == ConnectionTag.DOCKER_VPN_1
                    else (0, 0)
                ),
            )
        )
        assert alpha_setup_params.features.error_notification_service
        alpha_setup_params.features.error_notification_service.allow_only_pq = False
        env = await exit_stack.enter_async_context(
            setup_environment(exit_stack, [alpha_setup_params], prepare_vpn=True)
        )

        alpha, *_ = env.nodes
        client_conn, *_ = [conn.connection for conn in env.connections]
        client_alpha, *_ = env.clients

        ip = await stun.get(client_conn, config.STUN_SERVER)
        assert ip == public_ip, f"wrong public IP before connecting to VPN {ip}"

        vpn_connection, *_ = await setup_connections(exit_stack, [vpn_conf.conn_tag])
        await exit_stack.enter_async_context(
            client_alpha.get_router().block_tcp_port(ENS_PORT)
        )

        await connect_vpn(
            client_conn,
            vpn_connection.connection,
            client_alpha,
            alpha.ip_addresses[0],
            vpn_conf.server_conf,
        )
