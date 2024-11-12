import config
import pytest
from contextlib import AsyncExitStack
from helpers import SetupParameters, setup_environment
from telio import Client
from utils import stun
from utils.bindings import TelioAdapterType
from utils.connection import Connection
from utils.connection_tracker import ConnectionLimits
from utils.connection_util import (
    generate_connection_tracker_config,
    ConnectionTag,
    new_connection_by_tag,
)
from utils.dns import query_dns
from utils.ping import ping


async def _connect_vpn_pq(
    client_conn: Connection,
    client: Client,
) -> None:
    wg_server = config.NLX_SERVER

    await client.connect_to_vpn(
        str(wg_server["ipv4"]),
        int(wg_server["port"]),
        str(wg_server["public_key"]),
        pq=True,
    )

    await ping(client_conn, config.PHOTO_ALBUM_IP)

    ip = await stun.get(client_conn, config.STUN_SERVER)
    assert ip == wg_server["ipv4"], f"wrong public IP when connected to VPN {ip}"


async def inspect_preshared_key(nlx_conn: Connection) -> str:
    output = await nlx_conn.create_process(
        ["nlx", "show", "nordlynx0", "dump"]
    ).execute()
    last = output.get_stdout().splitlines()[-1]
    preshared = last.split()[1]

    assert preshared != "(none)", "Preshared key is not assigned"
    return preshared


@pytest.mark.parametrize(
    "alpha_setup_params, public_ip",
    [
        pytest.param(
            SetupParameters(
                connection_tag=ConnectionTag.DOCKER_CONE_CLIENT_1,
                adapter_type_override=TelioAdapterType.NEP_TUN,
                connection_tracker_config=generate_connection_tracker_config(
                    ConnectionTag.DOCKER_CONE_CLIENT_1,
                    stun_limits=ConnectionLimits(1, 1),
                    nlx_1_limits=ConnectionLimits(1, 2),
                ),
                is_meshnet=False,
            ),
            "10.0.254.1",
        ),
        pytest.param(
            SetupParameters(
                connection_tag=ConnectionTag.DOCKER_CONE_CLIENT_1,
                adapter_type_override=TelioAdapterType.LINUX_NATIVE_TUN,
                connection_tracker_config=generate_connection_tracker_config(
                    ConnectionTag.DOCKER_CONE_CLIENT_1,
                    stun_limits=ConnectionLimits(1, 1),
                    nlx_1_limits=ConnectionLimits(1, 2),
                ),
                is_meshnet=False,
            ),
            "10.0.254.1",
            marks=pytest.mark.linux_native,
        ),
        pytest.param(
            SetupParameters(
                connection_tag=ConnectionTag.WINDOWS_VM_1,
                adapter_type_override=TelioAdapterType.WINDOWS_NATIVE_TUN,
                connection_tracker_config=generate_connection_tracker_config(
                    ConnectionTag.WINDOWS_VM_1,
                    stun_limits=ConnectionLimits(1, 1),
                    nlx_1_limits=ConnectionLimits(1, 2),
                ),
                is_meshnet=False,
            ),
            "10.0.254.7",
            marks=[
                pytest.mark.windows,
            ],
        ),
        pytest.param(
            SetupParameters(
                connection_tag=ConnectionTag.WINDOWS_VM_1,
                adapter_type_override=TelioAdapterType.WIREGUARD_GO_TUN,
                connection_tracker_config=generate_connection_tracker_config(
                    ConnectionTag.WINDOWS_VM_1,
                    stun_limits=ConnectionLimits(1, 1),
                    nlx_1_limits=ConnectionLimits(1, 2),
                ),
                is_meshnet=False,
            ),
            "10.0.254.7",
            marks=[
                pytest.mark.windows,
            ],
        ),
        pytest.param(
            SetupParameters(
                connection_tag=ConnectionTag.MAC_VM,
                adapter_type_override=TelioAdapterType.NEP_TUN,
                connection_tracker_config=generate_connection_tracker_config(
                    ConnectionTag.MAC_VM,
                    stun_limits=ConnectionLimits(1, 1),
                    nlx_1_limits=ConnectionLimits(1, 2),
                ),
                is_meshnet=False,
            ),
            "10.0.254.7",
            marks=pytest.mark.mac,
        ),
    ],
)
async def test_pq_vpn_connection(
    alpha_setup_params: SetupParameters,
    public_ip: str,
) -> None:
    async with AsyncExitStack() as exit_stack:
        env = await exit_stack.enter_async_context(
            setup_environment(exit_stack, [alpha_setup_params])
        )

        client_conn, *_ = [conn.connection for conn in env.connections]
        client_alpha, *_ = env.clients

        ip = await stun.get(client_conn, config.STUN_SERVER)
        assert ip == public_ip, f"wrong public IP before connecting to VPN {ip}"

        await _connect_vpn_pq(
            client_conn,
            client_alpha,
        )


@pytest.mark.parametrize(
    "alpha_setup_params, public_ip",
    [
        pytest.param(
            SetupParameters(
                connection_tag=ConnectionTag.DOCKER_CONE_CLIENT_1,
                adapter_type_override=TelioAdapterType.NEP_TUN,
                connection_tracker_config=generate_connection_tracker_config(
                    ConnectionTag.DOCKER_CONE_CLIENT_1,
                    stun_limits=ConnectionLimits(1, 1),
                    nlx_1_limits=ConnectionLimits(1, 2),
                ),
                is_meshnet=False,
            ),
            "10.0.254.1",
        ),
        pytest.param(
            SetupParameters(
                connection_tag=ConnectionTag.DOCKER_CONE_CLIENT_1,
                adapter_type_override=TelioAdapterType.LINUX_NATIVE_TUN,
                connection_tracker_config=generate_connection_tracker_config(
                    ConnectionTag.DOCKER_CONE_CLIENT_1,
                    stun_limits=ConnectionLimits(1, 1),
                    nlx_1_limits=ConnectionLimits(1, 2),
                ),
                is_meshnet=False,
            ),
            "10.0.254.1",
            marks=pytest.mark.linux_native,
        ),
        pytest.param(
            SetupParameters(
                connection_tag=ConnectionTag.WINDOWS_VM_1,
                adapter_type_override=TelioAdapterType.WINDOWS_NATIVE_TUN,
                connection_tracker_config=generate_connection_tracker_config(
                    ConnectionTag.WINDOWS_VM_1,
                    stun_limits=ConnectionLimits(1, 1),
                    nlx_1_limits=ConnectionLimits(1, 2),
                ),
                is_meshnet=False,
            ),
            "10.0.254.7",
            marks=[
                pytest.mark.windows,
            ],
        ),
        pytest.param(
            SetupParameters(
                connection_tag=ConnectionTag.WINDOWS_VM_1,
                adapter_type_override=TelioAdapterType.WIREGUARD_GO_TUN,
                connection_tracker_config=generate_connection_tracker_config(
                    ConnectionTag.WINDOWS_VM_1,
                    stun_limits=ConnectionLimits(1, 1),
                    nlx_1_limits=ConnectionLimits(1, 2),
                ),
                is_meshnet=False,
            ),
            "10.0.254.7",
            marks=[
                pytest.mark.windows,
            ],
        ),
        pytest.param(
            SetupParameters(
                connection_tag=ConnectionTag.MAC_VM,
                adapter_type_override=TelioAdapterType.NEP_TUN,
                connection_tracker_config=generate_connection_tracker_config(
                    ConnectionTag.MAC_VM,
                    stun_limits=ConnectionLimits(1, 1),
                    nlx_1_limits=ConnectionLimits(1, 2),
                ),
                is_meshnet=False,
            ),
            "10.0.254.7",
            marks=pytest.mark.mac,
        ),
    ],
)
async def test_pq_vpn_rekey(
    alpha_setup_params: SetupParameters,
    public_ip: str,
) -> None:
    # Set rekey interval to some small value
    alpha_setup_params.features.post_quantum_vpn.rekey_interval_s = 2

    async with AsyncExitStack() as exit_stack:
        env = await exit_stack.enter_async_context(
            setup_environment(exit_stack, [alpha_setup_params])
        )

        client_conn, *_ = [conn.connection for conn in env.connections]
        client_alpha, *_ = env.clients

        ip = await stun.get(client_conn, config.STUN_SERVER)
        assert ip == public_ip, f"wrong public IP before connecting to VPN {ip}"

        await _connect_vpn_pq(
            client_conn,
            client_alpha,
        )

        nlx_conn = await exit_stack.enter_async_context(
            new_connection_by_tag(ConnectionTag.DOCKER_NLX_1)
        )

        preshared_before = inspect_preshared_key(nlx_conn)
        await client_alpha.wait_for_log("Successful PQ REKEY")

        preshared_after = inspect_preshared_key(nlx_conn)
        assert (
            preshared_after != preshared_before
        ), "Preshared key not changed on the nlx server"

        ip = await stun.get(client_conn, config.STUN_SERVER)
        assert (
            ip == config.NLX_SERVER["ipv4"]
        ), f"wrong public IP when connected to VPN {ip}"

        await ping(client_conn, config.PHOTO_ALBUM_IP)


@pytest.mark.parametrize(
    "alpha_setup_params",
    [
        pytest.param(
            SetupParameters(
                connection_tag=ConnectionTag.DOCKER_CONE_CLIENT_1,
                adapter_type_override=TelioAdapterType.NEP_TUN,
                connection_tracker_config=generate_connection_tracker_config(
                    ConnectionTag.DOCKER_CONE_CLIENT_1,
                    nlx_1_limits=ConnectionLimits(1, 2),
                ),
                is_meshnet=False,
            ),
        ),
        pytest.param(
            SetupParameters(
                connection_tag=ConnectionTag.DOCKER_CONE_CLIENT_1,
                adapter_type_override=TelioAdapterType.LINUX_NATIVE_TUN,
                connection_tracker_config=generate_connection_tracker_config(
                    ConnectionTag.DOCKER_CONE_CLIENT_1,
                    nlx_1_limits=ConnectionLimits(1, 2),
                ),
                is_meshnet=False,
            ),
            marks=pytest.mark.linux_native,
        ),
        pytest.param(
            SetupParameters(
                connection_tag=ConnectionTag.WINDOWS_VM_1,
                adapter_type_override=TelioAdapterType.WINDOWS_NATIVE_TUN,
                connection_tracker_config=generate_connection_tracker_config(
                    ConnectionTag.WINDOWS_VM_1,
                    nlx_1_limits=ConnectionLimits(1, 2),
                ),
                is_meshnet=False,
            ),
            marks=[
                pytest.mark.windows,
            ],
        ),
        pytest.param(
            SetupParameters(
                connection_tag=ConnectionTag.WINDOWS_VM_1,
                adapter_type_override=TelioAdapterType.WIREGUARD_GO_TUN,
                connection_tracker_config=generate_connection_tracker_config(
                    ConnectionTag.WINDOWS_VM_1,
                    nlx_1_limits=ConnectionLimits(1, 2),
                ),
                is_meshnet=False,
            ),
            marks=[
                pytest.mark.windows,
            ],
        ),
        pytest.param(
            SetupParameters(
                connection_tag=ConnectionTag.MAC_VM,
                adapter_type_override=TelioAdapterType.NEP_TUN,
                connection_tracker_config=generate_connection_tracker_config(
                    ConnectionTag.MAC_VM,
                    nlx_1_limits=ConnectionLimits(1, 2),
                ),
                is_meshnet=False,
            ),
            marks=pytest.mark.mac,
        ),
    ],
)
async def test_dns_with_pq(
    alpha_setup_params: SetupParameters,
) -> None:
    async with AsyncExitStack() as exit_stack:
        env = await exit_stack.enter_async_context(
            setup_environment(exit_stack, [alpha_setup_params])
        )

        client_conn, *_ = [conn.connection for conn in env.connections]
        client, *_ = env.clients

        wg_srv = config.NLX_SERVER

        await client.enable_magic_dns(["10.0.80.82"])

        await client.connect_to_vpn(
            str(wg_srv["ipv4"]),
            int(wg_srv["port"]),
            str(wg_srv["public_key"]),
            pq=False,
        )
        await ping(client_conn, config.PHOTO_ALBUM_IP)

        # Expect this to work
        await query_dns(client_conn, "google.com")

        await client.disconnect_from_vpn(str(wg_srv["public_key"]))

        await client.connect_to_vpn(
            str(wg_srv["ipv4"]),
            int(wg_srv["port"]),
            str(wg_srv["public_key"]),
            pq=True,
        )
        await ping(client_conn, config.PHOTO_ALBUM_IP)

        # Expect this to work as well after the secret key change
        await query_dns(client_conn, "google.com")
