import asyncio
import base64
import pytest
from contextlib import AsyncExitStack
from tests import config
from tests.helpers import (
    SetupParameters,
    setup_api,
    setup_environment,
    setup_connections,
)
from tests.helpers_ens import (
    get_grpc_tls_fingerprint_from_server,
    get_grpc_tls_root_certificate_from_server,
    get_grpc_tls_root_certificate,
    get_grpc_tls_fingerprint,
    generate_incorrect_certificate,
    trigger_connection_error,
    set_vpn_server_private_key,
    ens_maintenance,
)
from tests.helpers_fakefm import stop_service, start_service, FakeFmClient
from tests.helpers_vpn import connect_vpn, VpnConfig
from tests.utils import stun
from tests.utils.bindings import (
    default_features,
    PathType,
    NodeState,
    RelayState,
    TelioAdapterType,
    VpnConnectionError,
    generate_secret_key,
)
from tests.utils.connection import ConnectionTag
from tests.utils.connection_util import (
    generate_connection_tracker_config,
    new_connection_by_tag,
)
from tests.utils.ping import ping
from tests.utils.router import IPProto, IPStack
from typing import cast

ENS_PORT = 993
ENS_LOG_STR = "Will start ENS monitoring"


@pytest.mark.nlx
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
            marks=pytest.mark.windows,
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
async def test_ens_server_maintenance(
    alpha_setup_params: SetupParameters,
    public_ip: str,
) -> None:
    vpn_conf = VpnConfig(config.NLX_SERVER, ConnectionTag.VM_LINUX_NLX_1, False)

    async with AsyncExitStack() as exit_stack:
        nlx_conn = await exit_stack.enter_async_context(
            new_connection_by_tag(ConnectionTag.VM_LINUX_NLX_1)
        )

        fingerprint = await get_grpc_tls_fingerprint_from_server(nlx_conn)
        root_certificate_b64 = await get_grpc_tls_root_certificate_from_server(nlx_conn)
        root_certificate = base64.b64decode(root_certificate_b64)

        alpha_setup_params.connection_tracker_config = (
            generate_connection_tracker_config(
                alpha_setup_params.connection_tag,
                stun_limits=(1, 1),
                nlx_1_limits=(
                    (1, 1)
                    if vpn_conf.conn_tag == ConnectionTag.VM_LINUX_NLX_1
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
            setup_environment(
                exit_stack,
                [alpha_setup_params],
                vpn=[ConnectionTag.VM_LINUX_NLX_1, ConnectionTag.DOCKER_VPN_1],
            )
        )

        client_conn, *_ = [conn.connection for conn in env.connections]
        client_alpha, *_ = env.clients

        ip = await stun.get(client_conn, config.STUN_SERVER)
        assert ip == public_ip, f"wrong public IP before connecting to VPN {ip}"

        await setup_connections(exit_stack, [vpn_conf.conn_tag])

        nlx_server_ip = cast(str, vpn_conf.server_conf["ipv4"])
        nlx_server_port = cast(int, vpn_conf.server_conf["port"])
        nlx_server_public_key = cast(str, vpn_conf.server_conf["public_key"])

        await client_alpha.connect_to_vpn(
            nlx_server_ip,
            nlx_server_port,
            nlx_server_public_key,
        )

        async with ens_maintenance(nlx_conn, nlx_server_ip):
            await client_alpha.wait_for_state_peer(
                nlx_server_public_key,
                [NodeState.CONNECTED],
                [PathType.DIRECT],
                True,
                True,
                vpn_connection_error=VpnConnectionError.SERVER_MAINTENANCE,
            )

            await client_alpha.log.wait_for_log(fingerprint)
            await client_alpha.log.wait_for_log(
                "(ConnectionError { code: ServerMaintenance, additional_info: None })"
            )


@pytest.mark.nlx
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
            marks=pytest.mark.windows,
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
async def test_ens_unauthenticated(
    alpha_setup_params: SetupParameters,
    public_ip: str,
) -> None:
    vpn_conf = VpnConfig(config.NLX_SERVER, ConnectionTag.VM_LINUX_NLX_1, False)

    async with AsyncExitStack() as exit_stack:
        nlx_conn = await exit_stack.enter_async_context(
            new_connection_by_tag(ConnectionTag.VM_LINUX_NLX_1)
        )

        await stop_service(nlx_conn, "fakefm.service")
        await start_service(nlx_conn, "fakefm_dynamic_api.service")

        try:
            fingerprint = await get_grpc_tls_fingerprint_from_server(nlx_conn)
            root_certificate_b64 = await get_grpc_tls_root_certificate_from_server(
                nlx_conn
            )
            root_certificate = base64.b64decode(root_certificate_b64)

            alpha_setup_params.connection_tracker_config = (
                generate_connection_tracker_config(
                    alpha_setup_params.connection_tag,
                    stun_limits=(1, 1),
                    nlx_1_limits=(
                        (1, 1)
                        if vpn_conf.conn_tag == ConnectionTag.VM_LINUX_NLX_1
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
                setup_environment(
                    exit_stack,
                    [alpha_setup_params],
                    vpn=[
                        ConnectionTag.VM_LINUX_NLX_1,
                        ConnectionTag.DOCKER_VPN_1,
                    ],
                )
            )

            client_conn, *_ = [conn.connection for conn in env.connections]
            client_alpha, *_ = env.clients

            ip = await stun.get(client_conn, config.STUN_SERVER)
            assert ip == public_ip, f"wrong public IP before connecting to VPN {ip}"

            await setup_connections(exit_stack, [vpn_conf.conn_tag])

            nlx_server_ip = cast(str, vpn_conf.server_conf["ipv4"])
            nlx_server_port = cast(int, vpn_conf.server_conf["port"])
            nlx_server_public_key = cast(str, vpn_conf.server_conf["public_key"])

            with pytest.raises(asyncio.TimeoutError):
                await client_alpha.connect_to_vpn(
                    nlx_server_ip,
                    nlx_server_port,
                    nlx_server_public_key,
                    timeout=5,
                )

            await client_alpha.wait_for_state_peer(
                nlx_server_public_key,
                [NodeState.CONNECTING],
                [PathType.DIRECT],
                True,
                True,
                vpn_connection_error=VpnConnectionError.UNAUTHENTICATED,
            )

            await client_alpha.log.wait_for_log(fingerprint)
            await client_alpha.log.wait_for_log(
                "(ConnectionError { code: Unauthenticated, additional_info: None })"
            )
        finally:
            await stop_service(nlx_conn, "fakefm_dynamic_api.service")
            await start_service(nlx_conn, "fakefm.service")


@pytest.mark.nlx
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
            marks=pytest.mark.windows,
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
    "beta_setup_params",
    [
        pytest.param(
            SetupParameters(
                connection_tag=ConnectionTag.DOCKER_CONE_CLIENT_2,
                adapter_type_override=TelioAdapterType.NEP_TUN,
                is_meshnet=False,
                features=default_features(
                    enable_error_notification_service=True,
                ),
            ),
        ),
    ],
)
async def test_ens_connection_limit_reached(
    alpha_setup_params: SetupParameters,
    public_ip: str,
    beta_setup_params: SetupParameters,
) -> None:
    vpn_conf = VpnConfig(config.NLX_SERVER, ConnectionTag.VM_LINUX_NLX_1, False)

    async with AsyncExitStack() as exit_stack:
        nlx_conn = await exit_stack.enter_async_context(
            new_connection_by_tag(ConnectionTag.VM_LINUX_NLX_1)
        )

        await stop_service(nlx_conn, "fakefm.service")
        await start_service(nlx_conn, "fakefm_dynamic_api.service")

        fakefm = await FakeFmClient.create(cast(str, vpn_conf.server_conf["ipv4"]))
        await fakefm.set_users_limits(1)  # Set user limits to 1

        try:
            fingerprint = await get_grpc_tls_fingerprint_from_server(nlx_conn)
            root_certificate_b64 = await get_grpc_tls_root_certificate_from_server(
                nlx_conn
            )
            root_certificate = base64.b64decode(root_certificate_b64)

            for setup_params in (alpha_setup_params, beta_setup_params):
                setup_params.connection_tracker_config = (
                    generate_connection_tracker_config(
                        setup_params.connection_tag,
                        stun_limits=(1, 1),
                        nlx_1_limits=(
                            (1, 1)
                            if vpn_conf.conn_tag == ConnectionTag.VM_LINUX_NLX_1
                            else (0, 0)
                        ),
                    )
                )

                assert setup_params.features.error_notification_service
                setup_params.features.error_notification_service.allow_only_pq = False
                setup_params.features.error_notification_service.root_certificate_override = (
                    root_certificate
                )

            env = await exit_stack.enter_async_context(
                setup_environment(
                    exit_stack,
                    [alpha_setup_params, beta_setup_params],
                    vpn=[
                        ConnectionTag.VM_LINUX_NLX_1,
                        ConnectionTag.DOCKER_VPN_1,
                    ],
                )
            )

            alpha_conn, beta_conn, *_ = [c.connection for c in env.connections]
            client_alpha, client_beta, *_ = env.clients

            ip = await stun.get(alpha_conn, config.STUN_SERVER)
            assert ip == public_ip, f"wrong public IP before connecting to VPN {ip}"

            _ = await stun.get(beta_conn, config.STUN_SERVER)

            await setup_connections(exit_stack, [vpn_conf.conn_tag])

            nlx_server_ip = cast(str, vpn_conf.server_conf["ipv4"])
            nlx_server_port = cast(int, vpn_conf.server_conf["port"])
            nlx_server_public_key = cast(str, vpn_conf.server_conf["public_key"])

            ens_username = "ens_test_user"
            await fakefm.add_allowed_user(ens_username, client_alpha.node.public_key)

            await client_alpha.connect_to_vpn(
                nlx_server_ip,
                nlx_server_port,
                nlx_server_public_key,
            )

            await client_alpha.log.wait_for_log(fingerprint)

            await fakefm.add_allowed_user(ens_username, client_beta.node.public_key)

            with pytest.raises(asyncio.TimeoutError):
                await client_beta.connect_to_vpn(
                    nlx_server_ip,
                    nlx_server_port,
                    nlx_server_public_key,
                    timeout=5,
                )

            await client_beta.log.wait_for_log(fingerprint)
            await client_beta.wait_for_state_peer(
                nlx_server_public_key,
                [NodeState.CONNECTING],
                [PathType.DIRECT],
                is_exit=True,
                is_vpn=True,
                vpn_connection_error=VpnConnectionError.CONNECTION_LIMIT_REACHED,
            )
        finally:
            await stop_service(nlx_conn, "fakefm_dynamic_api.service")
            await start_service(nlx_conn, "fakefm.service")


@pytest.mark.nlx
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
            marks=pytest.mark.windows,
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
    "beta_setup_params",
    [
        pytest.param(
            SetupParameters(
                connection_tag=ConnectionTag.DOCKER_CONE_CLIENT_2,
                adapter_type_override=TelioAdapterType.NEP_TUN,
                is_meshnet=False,
                features=default_features(
                    enable_error_notification_service=True,
                ),
            ),
        ),
    ],
)
async def test_ens_superseded(
    alpha_setup_params: SetupParameters,
    public_ip: str,
    beta_setup_params: SetupParameters,
) -> None:
    vpn_conf = VpnConfig(config.NLX_SERVER, ConnectionTag.VM_LINUX_NLX_1, False)

    async with AsyncExitStack() as exit_stack:
        nlx_conn = await exit_stack.enter_async_context(
            new_connection_by_tag(ConnectionTag.VM_LINUX_NLX_1)
        )

        fingerprint = await get_grpc_tls_fingerprint_from_server(nlx_conn)
        root_certificate_b64 = await get_grpc_tls_root_certificate_from_server(nlx_conn)
        root_certificate = base64.b64decode(root_certificate_b64)

        for setup_params in (alpha_setup_params, beta_setup_params):
            setup_params.connection_tracker_config = generate_connection_tracker_config(
                setup_params.connection_tag,
                stun_limits=(1, 1),
                nlx_1_limits=(
                    (1, 1)
                    if vpn_conf.conn_tag == ConnectionTag.VM_LINUX_NLX_1
                    else (0, 0)
                ),
            )

            assert setup_params.features.error_notification_service
            setup_params.features.error_notification_service.allow_only_pq = False
            setup_params.features.error_notification_service.root_certificate_override = (
                root_certificate
            )

        env = await exit_stack.enter_async_context(
            setup_environment(
                exit_stack,
                [alpha_setup_params, beta_setup_params],
                vpn=[ConnectionTag.VM_LINUX_NLX_1, ConnectionTag.DOCKER_VPN_1],
            )
        )

        alpha_conn, beta_conn, *_ = [c.connection for c in env.connections]
        client_alpha, client_beta, *_ = env.clients

        ip = await stun.get(alpha_conn, config.STUN_SERVER)
        assert ip == public_ip, f"wrong public IP before connecting to VPN {ip}"

        _ = await stun.get(beta_conn, config.STUN_SERVER)

        new_secret_key = generate_secret_key()
        await client_alpha.set_secret_key(new_secret_key)
        await client_beta.set_secret_key(new_secret_key)

        await setup_connections(exit_stack, [vpn_conf.conn_tag])

        nlx_server_ip = cast(str, vpn_conf.server_conf["ipv4"])
        nlx_server_port = cast(int, vpn_conf.server_conf["port"])
        nlx_server_public_key = cast(str, vpn_conf.server_conf["public_key"])

        await client_alpha.connect_to_vpn(
            nlx_server_ip,
            nlx_server_port,
            nlx_server_public_key,
        )

        await client_alpha.log.wait_for_log(fingerprint)

        await client_beta.connect_to_vpn(
            nlx_server_ip,
            nlx_server_port,
            nlx_server_public_key,
        )

        await client_beta.log.wait_for_log(fingerprint)

        await client_alpha.wait_for_state_peer(
            nlx_server_public_key,
            [NodeState.CONNECTED],
            list(PathType),
            is_exit=True,
            is_vpn=True,
            vpn_connection_error=VpnConnectionError.SUPERSEDED,
        )


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
async def test_ens_connection_error_unknown(
    alpha_setup_params: SetupParameters,
    public_ip: str,
) -> None:
    vpn_conf = VpnConfig(config.WG_SERVER, ConnectionTag.DOCKER_VPN_1, True)
    vpn_ip = str(vpn_conf.server_conf["ipv4"])
    vpn_port = cast(int, vpn_conf.server_conf["port"])
    vpn_public_key = str(vpn_conf.server_conf["public_key"])
    vpn_private_key = str(vpn_conf.server_conf["private_key"])

    error_code = VpnConnectionError.UNKNOWN

    fingerprint = await get_grpc_tls_fingerprint(vpn_ip)
    root_certificate_b64 = await get_grpc_tls_root_certificate(vpn_ip)
    root_certificate: bytes = base64.b64decode(root_certificate_b64)

    async with AsyncExitStack() as exit_stack:
        await set_vpn_server_private_key(
            vpn_ip,
            vpn_private_key,
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
            setup_environment(
                exit_stack,
                [alpha_setup_params],
                vpn=[ConnectionTag.VM_LINUX_NLX_1, ConnectionTag.DOCKER_VPN_1],
            )
        )

        client_conn, *_ = [conn.connection for conn in env.connections]
        client_alpha, *_ = env.clients

        ip = await stun.get(client_conn, config.STUN_SERVER)
        assert ip == public_ip, f"wrong public IP before connecting to VPN {ip}"

        await setup_connections(exit_stack, [vpn_conf.conn_tag])

        await client_alpha.connect_to_vpn(
            vpn_ip,
            vpn_port,
            vpn_public_key,
        )

        additional_info = "some additional info"
        await trigger_connection_error(vpn_ip, error_code.value, additional_info)
        await client_alpha.wait_for_state_peer(
            vpn_conf.server_conf["public_key"],
            [NodeState.CONNECTED],
            [PathType.DIRECT],
            True,
            True,
            vpn_connection_error=error_code,
        )
        await client_alpha.log.wait_for_log(additional_info)
        await client_alpha.log.wait_for_log(fingerprint)


@pytest.mark.nlx
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
    vpn_conf = VpnConfig(config.NLX_SERVER, ConnectionTag.VM_LINUX_NLX_1, False)

    async with AsyncExitStack() as exit_stack:
        nlx_conn = await exit_stack.enter_async_context(
            new_connection_by_tag(ConnectionTag.VM_LINUX_NLX_1)
        )
        fingerprint = await get_grpc_tls_fingerprint_from_server(nlx_conn)
        root_certificate = await generate_incorrect_certificate(
            str(config.WG_SERVER["ipv4"])
        )  # take incorrect certificate from WG server

        alpha_setup_params.connection_tracker_config = (
            generate_connection_tracker_config(
                alpha_setup_params.connection_tag,
                stun_limits=(1, 1),
                nlx_1_limits=(
                    (1, 1)
                    if vpn_conf.conn_tag == ConnectionTag.VM_LINUX_NLX_1
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
            setup_environment(
                exit_stack,
                [alpha_setup_params],
                vpn=[ConnectionTag.VM_LINUX_NLX_1, ConnectionTag.DOCKER_VPN_1],
            )
        )

        client_conn, *_ = [conn.connection for conn in env.connections]
        client_alpha, *_ = env.clients

        ip = await stun.get(client_conn, config.STUN_SERVER)
        assert ip == public_ip, f"wrong public IP before connecting to VPN {ip}"

        await setup_connections(exit_stack, [vpn_conf.conn_tag])

        nlx_server_ip = cast(str, vpn_conf.server_conf["ipv4"])
        nlx_server_port = cast(int, vpn_conf.server_conf["port"])
        nlx_server_public_key = cast(str, vpn_conf.server_conf["public_key"])

        await client_alpha.connect_to_vpn(
            nlx_server_ip,
            nlx_server_port,
            nlx_server_public_key,
        )

        with pytest.raises(asyncio.TimeoutError):
            await client_alpha.wait_for_state_peer(
                nlx_server_public_key,
                [NodeState.CONNECTED],
                [PathType.DIRECT],
                True,
                True,
                timeout=15,
                vpn_connection_error=VpnConnectionError.UNKNOWN,
            )
        await client_alpha.log.wait_for_log(fingerprint)
        await client_alpha.log.wait_for_log("InvalidCertificate(UnknownIssuer)")


@pytest.mark.nlx
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
    vpn_conf = VpnConfig(config.NLX_SERVER, ConnectionTag.VM_LINUX_NLX_1, False)

    async with AsyncExitStack() as exit_stack:
        alpha_setup_params.connection_tracker_config = (
            generate_connection_tracker_config(
                alpha_setup_params.connection_tag,
                stun_limits=(1, 1),
                nlx_1_limits=(
                    (1, 1)
                    if vpn_conf.conn_tag == ConnectionTag.VM_LINUX_NLX_1
                    else (0, 0)
                ),
            )
        )
        assert alpha_setup_params.features.error_notification_service
        alpha_setup_params.features.error_notification_service.allow_only_pq = False
        env = await exit_stack.enter_async_context(
            setup_environment(
                exit_stack,
                [alpha_setup_params],
                vpn=[ConnectionTag.VM_LINUX_NLX_1, ConnectionTag.DOCKER_VPN_1],
            )
        )

        alpha, *_ = env.nodes
        client_conn, *_ = [conn.connection for conn in env.connections]
        client_alpha, *_ = env.clients

        ip = await stun.get(client_conn, config.STUN_SERVER)
        assert ip == public_ip, f"wrong public IP before connecting to VPN {ip}"

        await setup_connections(exit_stack, [vpn_conf.conn_tag])
        await exit_stack.enter_async_context(
            client_alpha.get_router().block_tcp_port(ENS_PORT)
        )

        await connect_vpn(
            client_conn,
            None,
            client_alpha,
            alpha.ip_addresses[0],
            vpn_conf.server_conf,
        )
