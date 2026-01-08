import asyncio
import pytest
from contextlib import AsyncExitStack
from datetime import datetime, timedelta
from tests import config
from tests.helpers import SetupParameters, setup_environment
from tests.telio import Client
from tests.utils import stun
from tests.utils.bindings import TelioAdapterType, NodeState, PathType
from tests.utils.connection import Connection, ConnectionTag
from tests.utils.connection_util import (
    generate_connection_tracker_config,
    new_connection_by_tag,
)
from tests.utils.dns import query_dns
from tests.utils.ping import ping
from tests.utils.testing import log_test_passed

EMPTY_PRESHARED_KEY_SLOT = "(none)"


# Returns the time at which the connection to the VPN server was established
async def _connect_vpn_pq(
    client_conn: Connection,
    client: Client,
) -> datetime:
    wg_server = config.NLX_SERVER

    await client.connect_to_vpn(
        str(wg_server["ipv4"]),
        int(wg_server["port"]),
        str(wg_server["public_key"]),
        pq=True,
        timeout=10,
    )

    connected = datetime.now()

    await ping(client_conn, config.PHOTO_ALBUM_IP)

    ip = await stun.get(client_conn, config.STUN_SERVER)
    assert ip == wg_server["ipv4"], f"wrong public IP when connected to VPN {ip}"

    return connected


async def read_preshared_key_slot(nlx_conn: Connection) -> str:
    output = await nlx_conn.create_process(
        ["nlx", "show", "nordlynx0", "dump"]
    ).execute()
    last = output.get_stdout().splitlines()[-1]
    return last.split()[1]


async def inspect_preshared_key(nlx_conn: Connection) -> str:
    preshared = await read_preshared_key_slot(nlx_conn)

    assert preshared != EMPTY_PRESHARED_KEY_SLOT, "Preshared key is not assigned"
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
                    stun_limits=(1, 1),
                    nlx_1_limits=(1, 2),
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
                    stun_limits=(1, 1),
                    nlx_1_limits=(1, 2),
                ),
                is_meshnet=False,
            ),
            "10.0.254.1",
            marks=pytest.mark.linux_native,
        ),
        pytest.param(
            SetupParameters(
                connection_tag=ConnectionTag.VM_WINDOWS_1,
                adapter_type_override=TelioAdapterType.WINDOWS_NATIVE_TUN,
                connection_tracker_config=generate_connection_tracker_config(
                    ConnectionTag.VM_WINDOWS_1,
                    stun_limits=(1, 1),
                    nlx_1_limits=(1, 2),
                ),
                is_meshnet=False,
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
                connection_tracker_config=generate_connection_tracker_config(
                    ConnectionTag.VM_MAC,
                    stun_limits=(1, 1),
                    nlx_1_limits=(1, 2),
                ),
                is_meshnet=False,
            ),
            "10.0.254.19",
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
            setup_environment(exit_stack, [alpha_setup_params], prepare_vpn=True)
        )

        client_conn, *_ = [conn.connection for conn in env.connections]
        client_alpha, *_ = env.clients

        ip = await stun.get(client_conn, config.STUN_SERVER)
        assert ip == public_ip, f"wrong public IP before connecting to VPN {ip}"

        await _connect_vpn_pq(
            client_conn,
            client_alpha,
        )
        log_test_passed()


@pytest.mark.parametrize(
    "alpha_setup_params, public_ip",
    [
        pytest.param(
            SetupParameters(
                connection_tag=ConnectionTag.DOCKER_CONE_CLIENT_1,
                adapter_type_override=TelioAdapterType.NEP_TUN,
                connection_tracker_config=generate_connection_tracker_config(
                    ConnectionTag.DOCKER_CONE_CLIENT_1,
                    stun_limits=(1, 1),
                    nlx_1_limits=(1, 2),
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
                    stun_limits=(1, 1),
                    nlx_1_limits=(1, 2),
                ),
                is_meshnet=False,
            ),
            "10.0.254.1",
            marks=pytest.mark.linux_native,
        ),
        pytest.param(
            SetupParameters(
                connection_tag=ConnectionTag.VM_WINDOWS_1,
                adapter_type_override=TelioAdapterType.WINDOWS_NATIVE_TUN,
                connection_tracker_config=generate_connection_tracker_config(
                    ConnectionTag.VM_WINDOWS_1,
                    stun_limits=(1, 1),
                    nlx_1_limits=(1, 2),
                ),
                is_meshnet=False,
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
                connection_tracker_config=generate_connection_tracker_config(
                    ConnectionTag.VM_MAC,
                    stun_limits=(1, 1),
                    nlx_1_limits=(1, 2),
                ),
                is_meshnet=False,
            ),
            "10.0.254.19",
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
            setup_environment(exit_stack, [alpha_setup_params], prepare_vpn=True)
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
            new_connection_by_tag(ConnectionTag.VM_LINUX_NLX_1)
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
        log_test_passed()


@pytest.mark.parametrize(
    "alpha_setup_params",
    [
        pytest.param(
            SetupParameters(
                connection_tag=ConnectionTag.DOCKER_CONE_CLIENT_1,
                adapter_type_override=TelioAdapterType.NEP_TUN,
                connection_tracker_config=generate_connection_tracker_config(
                    ConnectionTag.DOCKER_CONE_CLIENT_1,
                    nlx_1_limits=(1, 2),
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
                    nlx_1_limits=(1, 2),
                ),
                is_meshnet=False,
            ),
            marks=pytest.mark.linux_native,
        ),
        pytest.param(
            SetupParameters(
                connection_tag=ConnectionTag.VM_WINDOWS_1,
                adapter_type_override=TelioAdapterType.WINDOWS_NATIVE_TUN,
                connection_tracker_config=generate_connection_tracker_config(
                    ConnectionTag.VM_WINDOWS_1,
                    nlx_1_limits=(1, 2),
                ),
                is_meshnet=False,
            ),
            marks=[
                pytest.mark.windows,
            ],
        ),
        pytest.param(
            SetupParameters(
                connection_tag=ConnectionTag.VM_MAC,
                adapter_type_override=TelioAdapterType.NEP_TUN,
                connection_tracker_config=generate_connection_tracker_config(
                    ConnectionTag.VM_MAC,
                    nlx_1_limits=(1, 2),
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
            setup_environment(exit_stack, [alpha_setup_params], prepare_vpn=True)
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
        log_test_passed()


@pytest.mark.parametrize(
    "setup",
    [
        pytest.param(
            SetupParameters(
                connection_tag=ConnectionTag.DOCKER_CONE_CLIENT_1,
                adapter_type_override=TelioAdapterType.NEP_TUN,
                connection_tracker_config=generate_connection_tracker_config(
                    ConnectionTag.DOCKER_CONE_CLIENT_1,
                    vpn_1_limits=(1, None),
                    nlx_1_limits=(1, 2),
                ),
                is_meshnet=False,
            ),
        ),
    ],
)
async def test_pq_vpn_silent_pq_upgrader(
    setup: SetupParameters,
) -> None:
    async with AsyncExitStack() as exit_stack:
        setup.features.post_quantum_vpn.handshake_retry_interval_s = 1

        env = await exit_stack.enter_async_context(
            setup_environment(exit_stack, [setup], prepare_vpn=True)
        )

        client_conn, *_ = [conn.connection for conn in env.connections]
        client, *_ = env.clients

        wg_server = config.WG_SERVER  # use non PQ server

        ip = str(wg_server["ipv4"])
        pubkey = str(wg_server["public_key"])
        port = int(wg_server["port"])

        await client.restart_interface()
        await client.get_router().create_vpn_route()
        client.get_runtime().allowed_pub_keys.add(pubkey)

        await client.get_proxy().connect_to_exit_node_pq(
            public_key=pubkey,
            allowed_ips=None,
            endpoint=f"{ip}:{port}",
        )

        await client.wait_for_state_peer(
            pubkey,
            [NodeState.CONNECTING],
            list(PathType),
            is_exit=True,
            is_vpn=True,
            timeout=1,
        )

        try:
            await client.wait_for_state_peer(
                pubkey,
                [NodeState.CONNECTED],
                list(PathType),
                is_exit=True,
                is_vpn=True,
                timeout=3,
            )
            raise Exception("This shouldn't connect succesfully")
        except TimeoutError:
            pass

        await client.disconnect_from_vpn(pubkey, timeout=4)
        await client.get_router().delete_vpn_route()

        # now connect to a good behaving PQ server
        await _connect_vpn_pq(client_conn, client)
        await ping(client_conn, config.PHOTO_ALBUM_IP)
        log_test_passed()


@pytest.mark.parametrize(
    "alpha_setup_params",
    [
        pytest.param(
            SetupParameters(
                connection_tag=ConnectionTag.DOCKER_CONE_CLIENT_1,
                adapter_type_override=TelioAdapterType.NEP_TUN,
                connection_tracker_config=generate_connection_tracker_config(
                    ConnectionTag.DOCKER_CONE_CLIENT_1,
                    nlx_1_limits=(1, 2),
                ),
                is_meshnet=False,
            ),
        ),
    ],
)
async def test_pq_vpn_upgrade_from_non_pq(
    alpha_setup_params: SetupParameters,
) -> None:
    async with AsyncExitStack() as exit_stack:
        alpha_setup_params.features.post_quantum_vpn.handshake_retry_interval_s = 1

        env = await exit_stack.enter_async_context(
            setup_environment(exit_stack, [alpha_setup_params], prepare_vpn=True)
        )

        client_conn, *_ = [conn.connection for conn in env.connections]
        client, *_ = env.clients

        nlx_conn = await exit_stack.enter_async_context(
            new_connection_by_tag(ConnectionTag.VM_LINUX_NLX_1)
        )

        wg_server = config.NLX_SERVER

        # non-PQ connection
        await client.connect_to_vpn(
            str(wg_server["ipv4"]),
            int(wg_server["port"]),
            str(wg_server["public_key"]),
            pq=False,
        )
        await ping(client_conn, config.PHOTO_ALBUM_IP)

        preshared = await read_preshared_key_slot(nlx_conn)
        assert preshared == EMPTY_PRESHARED_KEY_SLOT

        # upgrade to PQ
        await client.disconnect_from_vpn(str(wg_server["public_key"]))
        await _connect_vpn_pq(client_conn, client)
        await ping(client_conn, config.PHOTO_ALBUM_IP)

        preshared = await read_preshared_key_slot(nlx_conn)
        assert preshared != EMPTY_PRESHARED_KEY_SLOT
        log_test_passed()


# Regression test for LLT-5884
@pytest.mark.timeout(240)
@pytest.mark.parametrize(
    "setup_params, public_ip",
    [
        pytest.param(
            SetupParameters(
                connection_tag=ConnectionTag.DOCKER_CONE_CLIENT_1,
                adapter_type_override=TelioAdapterType.NEP_TUN,
                connection_tracker_config=generate_connection_tracker_config(
                    ConnectionTag.DOCKER_CONE_CLIENT_1,
                    stun_limits=(1, 1),
                    nlx_1_limits=(1, 4),
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
                    stun_limits=(1, 1),
                    nlx_1_limits=(1, 4),
                ),
                is_meshnet=False,
            ),
            "10.0.254.1",
            marks=pytest.mark.linux_native,
        ),
        # TODO(LLT-6000)
        # pytest.param(
        #     SetupParameters(
        #         connection_tag=ConnectionTag.VM_WINDOWS_1,
        #         adapter_type_override=TelioAdapterType.WINDOWS_NATIVE_TUN,
        #         connection_tracker_config=generate_connection_tracker_config(
        #             ConnectionTag.VM_WINDOWS_1,
        #             stun_limits=(1, 1),
        #             nlx_1_limits=(1, 4),
        #         ),
        #         is_meshnet=False,
        #     ),
        #     "10.0.254.15",
        #     marks=pytest.mark.windows,
        # ),
    ],
)
async def test_pq_vpn_handshake_after_nonet(
    setup_params: SetupParameters,
    public_ip: str,
) -> None:
    async with AsyncExitStack() as exit_stack:
        env = await exit_stack.enter_async_context(
            setup_environment(
                exit_stack,
                [setup_params],
                prepare_vpn=True,
            )
        )

        client_conn, *_ = [conn.connection for conn in env.connections]
        client_alpha, *_ = env.clients

        ip = await stun.get(client_conn, config.STUN_SERVER)
        assert ip == public_ip, f"wrong public IP before connecting to VPN {ip}"

        pq_connected = await _connect_vpn_pq(
            client_conn,
            client_alpha,
        )
        just_before_pq_restart = pq_connected + timedelta(seconds=120)

        async with client_alpha.get_router().break_udp_conn_to_host(
            str(config.NLX_SERVER["ipv4"])
        ):
            sleep_secs = (just_before_pq_restart - datetime.now()).total_seconds()
            await asyncio.sleep(sleep_secs)

            client_log = (await client_alpha.get_log()).lower()
            log_line = "Restarting postquantum entity".lower()
            occurrences = client_log.count(log_line)

            assert (
                occurrences == 0
            ), "Found PQ restart log even though PQ should not have been restarted yet"

            await client_alpha.wait_for_log("Restarting postquantum entity")

        await client_alpha.wait_for_state_peer(
            config.NLX_SERVER["public_key"],
            [NodeState.CONNECTED],
            list(PathType),
            is_exit=True,
            is_vpn=True,
        )

        await ping(client_conn, config.PHOTO_ALBUM_IP)
        log_test_passed()


@pytest.mark.timeout(240)
@pytest.mark.parametrize(
    "setup_params, public_ip",
    [
        pytest.param(
            SetupParameters(
                connection_tag=ConnectionTag.DOCKER_CONE_CLIENT_1,
                adapter_type_override=TelioAdapterType.NEP_TUN,
                connection_tracker_config=generate_connection_tracker_config(
                    ConnectionTag.DOCKER_CONE_CLIENT_1,
                    stun_limits=(1, 1),
                    nlx_1_limits=(1, 4),
                ),
                is_meshnet=False,
            ),
            "10.0.254.1",
        ),
    ],
)
async def test_pq_no_false_restart(
    setup_params: SetupParameters,
    public_ip: str,
) -> None:
    async with AsyncExitStack() as exit_stack:
        env = await exit_stack.enter_async_context(
            setup_environment(
                exit_stack,
                [setup_params],
                prepare_vpn=True,
            )
        )

        client_conn, *_ = [conn.connection for conn in env.connections]
        client_alpha, *_ = env.clients

        ip = await stun.get(client_conn, config.STUN_SERVER)
        assert ip == public_ip, f"wrong public IP before connecting to VPN {ip}"

        await _connect_vpn_pq(
            client_conn,
            client_alpha,
        )

        await asyncio.sleep(200)

        log = (await client_alpha.get_log()).lower()
        log_line = "Restarting postquantum entity".lower()
        occurrences = log.count(log_line)

        assert (
            occurrences == 0
        ), "Found PQ restart log even though PQ should not have been restarted"
        log_test_passed()
