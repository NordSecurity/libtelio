import asyncio
import pytest
from collections.abc import AsyncIterator
from contextlib import AsyncExitStack
from datetime import datetime, timedelta
from tests import config
from tests.helpers import SetupParameters, Environment, setup_environment
from tests.libtelio_client import Client
from tests.uniffi.telio_bindings import VpnConnectionConfigBuilder
from tests.utils import stun
from tests.utils.bindings import TelioAdapterType, NodeState, PathType
from tests.utils.connection import Connection, ConnectionTag
from tests.utils.connection_util import (
    generate_connection_tracker_config,
    new_connection_by_tag,
)
from tests.utils.dns import query_dns
from tests.utils.ping import ping
from tests.utils.python import get_python_binary
from tests.utils.router import IPStack

EMPTY_PRESHARED_KEY_SLOT = "(none)"
NLX_INTERFACE = "nlx0"
PQ_VERSION_V1 = 1
PQ_VERSION_V2 = 2
PQ_VERSIONS = [PQ_VERSION_V1, PQ_VERSION_V2]
PQ_REKEY_METHOD = 1
PQ_UPGRADER_IP = "10.5.0.1"
PQ_UPGRADER_PORT = 6480
PQ_UPGRADER_REPLY_TIMEOUT_S = 3
SHORT_PQ_REKEY_INTERVAL_S = 2
LONG_PQ_REKEY_INTERVAL_S = 3600
PQ_HANDSHAKE_RETRY_INTERVAL_S = 5
PQ_REKEY_SUCCESS_LOG = "Successful PQ REKEY"
PQ_RESTART_LOG = "Restarting postquantum entity"
PQ_V1_REKEY_SCRIPT = f"""
import socket, struct
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout({PQ_UPGRADER_REPLY_TIMEOUT_S})
s.sendto(struct.pack("<II", {PQ_VERSION_V1}, {PQ_REKEY_METHOD}), ("{PQ_UPGRADER_IP}", {PQ_UPGRADER_PORT}))
try:
    print(s.recv(4096).hex())
except socket.timeout:
    print("timeout")
"""


# Module-level override — all standalone PQ tests use NLX VPN
@pytest.fixture(name="vpn_tags")
def _vpn_tags() -> list:
    return [ConnectionTag.VM_LINUX_NLX_1]


# Returns the time at which the connection to the VPN server was established
async def _connect_vpn_pq(
    client_conn: Connection,
    client: Client,
) -> datetime:
    wg_server = config.NLX_SERVER

    await client.vpn.connect(
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
        ["nlx", "show", NLX_INTERFACE, "dump"]
    ).execute()
    last = output.get_stdout().splitlines()[-1]
    return last.split()[1]


async def inspect_preshared_key(nlx_conn: Connection) -> str:
    preshared = await read_preshared_key_slot(nlx_conn)

    assert preshared != EMPTY_PRESHARED_KEY_SLOT, "Preshared key is not assigned"
    return preshared


class TestPqVpnConnection:
    """Tests using PQ VPN with version mutation."""

    @pytest.fixture(autouse=True)
    def _mutate_pq_version(self, alpha_setup_params: SetupParameters, pq_version: int):
        alpha_setup_params.features.post_quantum_vpn.version = pq_version

    @pytest.mark.nlx
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
                        nlx_1_limits=(2, 2),
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
                        nlx_1_limits=(2, 2),
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
                        nlx_1_limits=(2, 2),
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
                        nlx_1_limits=(2, 2),
                    ),
                    is_meshnet=False,
                ),
                "10.0.254.19",
                marks=pytest.mark.mac,
            ),
            pytest.param(
                SetupParameters(
                    connection_tag=ConnectionTag.VM_ANDROID_1,
                    adapter_type_override=TelioAdapterType.NEP_TUN,
                    ip_stack=IPStack.IPv4,
                    is_meshnet=False,
                ),
                "10.0.254.24",
                marks=pytest.mark.android,
            ),
        ],
    )
    @pytest.mark.parametrize(
        "pq_version",
        PQ_VERSIONS,
    )
    async def test_pq_vpn_connection(
        self,
        alpha_setup_params: SetupParameters,  # pylint: disable=unused-argument
        public_ip: str,
        pq_version: int,  # pylint: disable=unused-argument
        env: Environment,
    ) -> None:
        client_conn, *_ = [conn.connection for conn in env.connections]
        client_alpha, *_ = env.clients

        ip = await stun.get(client_conn, config.STUN_SERVER)
        assert ip == public_ip, f"wrong public IP before connecting to VPN {ip}"

        await _connect_vpn_pq(
            client_conn,
            client_alpha,
        )


class TestPqVpnRekey:
    """Tests using PQ VPN with version + rekey mutation."""

    @pytest.fixture(autouse=True)
    def _mutate_pq_rekey(self, alpha_setup_params: SetupParameters, pq_version: int):
        alpha_setup_params.features.post_quantum_vpn.rekey_interval_s = (
            SHORT_PQ_REKEY_INTERVAL_S
        )
        alpha_setup_params.features.post_quantum_vpn.version = pq_version

    @pytest.mark.nlx
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
                        nlx_1_limits=(2, 2),
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
                        nlx_1_limits=(2, 2),
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
                        nlx_1_limits=(2, 2),
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
                        nlx_1_limits=(2, 2),
                    ),
                    is_meshnet=False,
                ),
                "10.0.254.19",
                marks=pytest.mark.mac,
            ),
            pytest.param(
                SetupParameters(
                    connection_tag=ConnectionTag.VM_ANDROID_1,
                    adapter_type_override=TelioAdapterType.NEP_TUN,
                    ip_stack=IPStack.IPv4,
                    is_meshnet=False,
                ),
                "10.0.254.24",
                marks=pytest.mark.android,
            ),
        ],
    )
    @pytest.mark.parametrize(
        "pq_version",
        PQ_VERSIONS,
    )
    async def test_pq_vpn_rekey(
        self,
        alpha_setup_params: SetupParameters,  # pylint: disable=unused-argument
        public_ip: str,
        pq_version: int,  # pylint: disable=unused-argument
        env: Environment,
    ) -> None:
        client_conn, *_ = [conn.connection for conn in env.connections]
        client_alpha, *_ = env.clients

        ip = await stun.get(client_conn, config.STUN_SERVER)
        assert ip == public_ip, f"wrong public IP before connecting to VPN {ip}"

        await _connect_vpn_pq(
            client_conn,
            client_alpha,
        )

        async with new_connection_by_tag(ConnectionTag.VM_LINUX_NLX_1) as nlx_conn:
            preshared_before = await inspect_preshared_key(nlx_conn)
            await client_alpha.log.wait_for(PQ_REKEY_SUCCESS_LOG, incremental=True)

            preshared_after = await inspect_preshared_key(nlx_conn)
            assert (
                preshared_after != preshared_before
            ), "Preshared key not changed on the nlx server"

        ip = await stun.get(client_conn, config.STUN_SERVER)
        assert (
            ip == config.NLX_SERVER["ipv4"]
        ), f"wrong public IP when connected to VPN {ip}"

        await ping(client_conn, config.PHOTO_ALBUM_IP)

    @pytest.mark.nlx
    @pytest.mark.parametrize(
        "alpha_setup_params",
        [
            pytest.param(
                SetupParameters(
                    connection_tag=ConnectionTag.DOCKER_CONE_CLIENT_1,
                    adapter_type_override=TelioAdapterType.NEP_TUN,
                    connection_tracker_config=generate_connection_tracker_config(
                        ConnectionTag.DOCKER_CONE_CLIENT_1,
                        nlx_1_limits=(2, 2),
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
                        nlx_1_limits=(2, 2),
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
                        nlx_1_limits=(2, 2),
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
                        nlx_1_limits=(2, 2),
                    ),
                    is_meshnet=False,
                ),
                marks=pytest.mark.mac,
            ),
            pytest.param(
                SetupParameters(
                    connection_tag=ConnectionTag.VM_ANDROID_1,
                    adapter_type_override=TelioAdapterType.NEP_TUN,
                    ip_stack=IPStack.IPv4,
                    is_meshnet=False,
                ),
                marks=pytest.mark.android,
            ),
        ],
    )
    @pytest.mark.parametrize(
        "pq_version",
        PQ_VERSIONS,
    )
    async def test_dns_with_pq(
        self,
        alpha_setup_params: SetupParameters,  # pylint: disable=unused-argument
        pq_version: int,  # pylint: disable=unused-argument
        env: Environment,
    ) -> None:
        client_conn, *_ = [conn.connection for conn in env.connections]
        client, *_ = env.clients

        wg_srv = config.NLX_SERVER

        await client.enable_magic_dns(["10.0.80.82"])

        await client.vpn.connect(
            str(wg_srv["ipv4"]),
            int(wg_srv["port"]),
            str(wg_srv["public_key"]),
            pq=False,
        )
        await ping(client_conn, config.PHOTO_ALBUM_IP)

        # Expect this to work
        await query_dns(client_conn, "google.com")

        await client.vpn.disconnect(str(wg_srv["public_key"]))

        await client.vpn.connect(
            str(wg_srv["ipv4"]),
            int(wg_srv["port"]),
            str(wg_srv["public_key"]),
            pq=True,
        )
        await ping(client_conn, config.PHOTO_ALBUM_IP)

        # Expect this to work as well after the secret key change
        await query_dns(client_conn, "google.com")


class TestPqVpnHandshake:
    """Tests using PQ VPN with version + handshake_retry_interval mutation."""

    @pytest.fixture(autouse=True)
    def _mutate_pq_handshake(
        self, alpha_setup_params: SetupParameters, pq_version: int
    ):
        alpha_setup_params.features.post_quantum_vpn.handshake_retry_interval_s = (
            PQ_HANDSHAKE_RETRY_INTERVAL_S
        )
        alpha_setup_params.features.post_quantum_vpn.version = pq_version

    @pytest.mark.nlx
    @pytest.mark.parametrize(
        "alpha_setup_params",
        [
            pytest.param(
                SetupParameters(
                    connection_tag=ConnectionTag.DOCKER_CONE_CLIENT_1,
                    adapter_type_override=TelioAdapterType.NEP_TUN,
                    connection_tracker_config=generate_connection_tracker_config(
                        ConnectionTag.DOCKER_CONE_CLIENT_1,
                        vpn_1_limits=(1, None),
                        nlx_1_limits=(2, 2),
                    ),
                    is_meshnet=False,
                ),
            ),
        ],
    )
    @pytest.mark.parametrize(
        "pq_version",
        PQ_VERSIONS,
    )
    async def test_pq_vpn_silent_pq_upgrader(
        self,
        alpha_setup_params: SetupParameters,  # pylint: disable=unused-argument
        pq_version: int,  # pylint: disable=unused-argument
        env: Environment,
    ) -> None:
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

        await client.events.wait_for_state_peer(
            pubkey,
            [NodeState.CONNECTING],
            list(PathType),
            is_exit=True,
            is_vpn=True,
            timeout=1,
        )

        try:
            await client.events.wait_for_state_peer(
                pubkey,
                [NodeState.CONNECTED],
                list(PathType),
                is_exit=True,
                is_vpn=True,
                timeout=3,
            )
            raise RuntimeError("This shouldn't connect succesfully")
        except TimeoutError:
            pass

        await client.vpn.disconnect(pubkey, timeout=4)
        await client.get_router().delete_vpn_route()

        # now connect to a good behaving PQ server
        await _connect_vpn_pq(client_conn, client)
        await ping(client_conn, config.PHOTO_ALBUM_IP)

    @pytest.mark.nlx
    @pytest.mark.parametrize(
        "alpha_setup_params",
        [
            pytest.param(
                SetupParameters(
                    connection_tag=ConnectionTag.DOCKER_CONE_CLIENT_1,
                    adapter_type_override=TelioAdapterType.NEP_TUN,
                    connection_tracker_config=generate_connection_tracker_config(
                        ConnectionTag.DOCKER_CONE_CLIENT_1,
                        nlx_1_limits=(2, 2),
                    ),
                    is_meshnet=False,
                ),
            ),
        ],
    )
    @pytest.mark.parametrize(
        "pq_version",
        PQ_VERSIONS,
    )
    async def test_pq_vpn_upgrade_from_non_pq(
        self,
        alpha_setup_params: SetupParameters,  # pylint: disable=unused-argument
        pq_version: int,  # pylint: disable=unused-argument
        env: Environment,
    ) -> None:
        client_conn, *_ = [conn.connection for conn in env.connections]
        client, *_ = env.clients

        async with new_connection_by_tag(ConnectionTag.VM_LINUX_NLX_1) as nlx_conn:
            wg_server = config.NLX_SERVER

            # non-PQ connection
            await client.vpn.connect(
                str(wg_server["ipv4"]),
                int(wg_server["port"]),
                str(wg_server["public_key"]),
                pq=False,
            )
            await ping(client_conn, config.PHOTO_ALBUM_IP)

            preshared = await read_preshared_key_slot(nlx_conn)
            assert preshared == EMPTY_PRESHARED_KEY_SLOT

            # upgrade to PQ
            await client.vpn.disconnect(str(wg_server["public_key"]))
            await _connect_vpn_pq(client_conn, client)
            await ping(client_conn, config.PHOTO_ALBUM_IP)

            preshared = await read_preshared_key_slot(nlx_conn)
            assert preshared != EMPTY_PRESHARED_KEY_SLOT


class PqV1RekeyAcceptedError(Exception):
    """Raised when nlx applies a v1 rekey to a v2 PQ session."""


# A v1 rekey has no auth tag and goes inside the VPN tunnel, so anything
# that can send traffic through the client's tunnel can send one. Remove
# xfail once nlx rejects rekeys whose version differs from the one used in
# the session's GET (LLTSS-1649).
@pytest.mark.xfail(
    strict=True,
    raises=PqV1RekeyAcceptedError,
    reason="nlx accepts unauthenticated v1 rekey for a v2 PQ session",
)
@pytest.mark.nlx
async def test_pq_v2_session_rejects_v1_rekey(exit_stack: AsyncExitStack) -> None:
    alpha_setup_params = SetupParameters(
        connection_tag=ConnectionTag.DOCKER_CONE_CLIENT_1,
        adapter_type_override=TelioAdapterType.NEP_TUN,
        connection_tracker_config=generate_connection_tracker_config(
            ConnectionTag.DOCKER_CONE_CLIENT_1,
            nlx_1_limits=(2, 2),
        ),
        is_meshnet=False,
    )
    alpha_setup_params.features.post_quantum_vpn.version = PQ_VERSION_V2
    alpha_setup_params.features.post_quantum_vpn.rekey_interval_s = (
        LONG_PQ_REKEY_INTERVAL_S
    )

    env = await exit_stack.enter_async_context(
        setup_environment(
            exit_stack, [alpha_setup_params], vpn=[ConnectionTag.VM_LINUX_NLX_1]
        )
    )
    client_conn, *_ = [conn.connection for conn in env.connections]
    client, *_ = env.clients

    await _connect_vpn_pq(client_conn, client)

    async with new_connection_by_tag(ConnectionTag.VM_LINUX_NLX_1) as nlx_conn:
        preshared_before = await inspect_preshared_key(nlx_conn)

        output = await client_conn.create_process(
            [get_python_binary(client_conn), "-c", PQ_V1_REKEY_SCRIPT]
        ).execute()

        preshared_after = await inspect_preshared_key(nlx_conn)
        if preshared_after != preshared_before:
            raise PqV1RekeyAcceptedError(
                "v1 rekey changed the PSK of a v2 PQ session, pq-upgrader reply:"
                f" {output.get_stdout()}"
            )

    await ping(client_conn, config.PHOTO_ALBUM_IP)


class TestNlxVpn:
    """Tests requiring NLX VPN with 1-node non-mesh (env)."""

    @pytest.fixture(name="vpn_tags")
    def _vpn_tags(self) -> list:
        return [ConnectionTag.VM_LINUX_NLX_1]

    # Regression test for LLT-5884
    @pytest.mark.nlx
    @pytest.mark.timeout(240)
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
                        nlx_1_limits=(4, 4),
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
                        nlx_1_limits=(4, 4),
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
        self,
        alpha_setup_params: SetupParameters,  # pylint: disable=unused-argument
        public_ip: str,
        env: Environment,
    ) -> None:
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

            client_log = (await client_alpha.log.get()).lower()
            log_line = PQ_RESTART_LOG.lower()
            occurrences = client_log.count(log_line)

            assert (
                occurrences == 0
            ), "Found PQ restart log even though PQ should not have been restarted yet"

            await client_alpha.log.wait_for(PQ_RESTART_LOG)

        await client_alpha.events.wait_for_state_peer(
            config.NLX_SERVER["public_key"],
            [NodeState.CONNECTED],
            list(PathType),
            is_exit=True,
            is_vpn=True,
        )

        await ping(client_conn, config.PHOTO_ALBUM_IP)

    @pytest.mark.nlx
    @pytest.mark.timeout(240)
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
                        nlx_1_limits=(2, 4),
                    ),
                    is_meshnet=False,
                ),
                "10.0.254.1",
            ),
        ],
    )
    async def test_pq_no_false_restart(
        self,
        alpha_setup_params: SetupParameters,  # pylint: disable=unused-argument
        public_ip: str,
        env: Environment,
    ) -> None:
        client_conn, *_ = [conn.connection for conn in env.connections]
        client_alpha, *_ = env.clients

        ip = await stun.get(client_conn, config.STUN_SERVER)
        assert ip == public_ip, f"wrong public IP before connecting to VPN {ip}"

        await _connect_vpn_pq(
            client_conn,
            client_alpha,
        )

        await asyncio.sleep(200)

        log = (await client_alpha.log.get()).lower()
        log_line = PQ_RESTART_LOG.lower()
        occurrences = log.count(log_line)

        assert (
            occurrences == 0
        ), "Found PQ restart log even though PQ should not have been restarted"


class TestCustomPqUpgraderIp:
    """Verify that we can still establsh a working PQ VPN connection with custom PQ
    upgrader IP.

    We add a secondary IP alias on the NLX container's WireGuard interface and install a
    DNAT rule that redirects PQ-upgrader traffic arriving at the alias back to the
    real upgrader IP. The client then uses the alias as the custom PQ Upgrader IP."""

    PQ_UPGRADER_REAL_IP = "10.5.0.1"
    PQ_UPGRADER_ALIAS_IP = "10.5.1.1"  # alias used only by this test
    PQ_UPGRADER_PORT = 6480

    async def _add_pq_upgrader_alias(self, nlx_conn: Connection) -> None:
        # 'replace' avoids "File exists" from a prior leaked alias.
        await nlx_conn.create_process([
            "ip",
            "addr",
            "replace",
            f"{self.PQ_UPGRADER_ALIAS_IP}/32",
            "dev",
            "nlx0",
        ]).execute()
        await nlx_conn.create_process([
            "iptables",
            "-t",
            "nat",
            "-A",
            "PREROUTING",
            "-d",
            self.PQ_UPGRADER_ALIAS_IP,
            "-p",
            "udp",
            "--dport",
            str(self.PQ_UPGRADER_PORT),
            "-j",
            "DNAT",
            "--to-destination",
            f"{self.PQ_UPGRADER_REAL_IP}:{self.PQ_UPGRADER_PORT}",
        ]).execute()

    async def _remove_pq_upgrader_alias(self, nlx_conn: Connection) -> None:
        iptables_del = (
            f"iptables -t nat -D PREROUTING"
            f" -d {self.PQ_UPGRADER_ALIAS_IP}"
            f" -p udp --dport {self.PQ_UPGRADER_PORT}"
            f" -j DNAT --to-destination {self.PQ_UPGRADER_REAL_IP}:{self.PQ_UPGRADER_PORT}"
            f" || true"
        )
        ip_del = f"ip addr del {self.PQ_UPGRADER_ALIAS_IP}/32 dev nlx0 || true"
        await nlx_conn.create_process(["bash", "-c", iptables_del]).execute()
        await nlx_conn.create_process(["bash", "-c", ip_del]).execute()

    @pytest.fixture(autouse=True)
    def _mutate_pq_version(self, alpha_setup_params: SetupParameters, pq_version: int):
        alpha_setup_params.features.post_quantum_vpn.version = pq_version

    @pytest.fixture
    def _mutate_pq_rekey_interval(self, alpha_setup_params: SetupParameters):
        alpha_setup_params.features.post_quantum_vpn.rekey_interval_s = 2

    @pytest.fixture
    async def pq_upgrader_alias(self) -> AsyncIterator[Connection]:
        async with new_connection_by_tag(ConnectionTag.VM_LINUX_NLX_1) as nlx_conn:
            try:
                await self._add_pq_upgrader_alias(nlx_conn)
                yield nlx_conn
            finally:
                await self._remove_pq_upgrader_alias(nlx_conn)

    @pytest.mark.nlx
    @pytest.mark.parametrize(
        "alpha_setup_params",
        [
            pytest.param(
                SetupParameters(
                    connection_tag=ConnectionTag.DOCKER_CONE_CLIENT_1,
                    adapter_type_override=TelioAdapterType.NEP_TUN,
                    connection_tracker_config=generate_connection_tracker_config(
                        ConnectionTag.DOCKER_CONE_CLIENT_1,
                        nlx_1_limits=(2, 2),
                    ),
                    is_meshnet=False,
                ),
            ),
        ],
    )
    @pytest.mark.parametrize(
        "pq_version",
        [pytest.param(1), pytest.param(2)],
    )
    async def test_pq_vpn_with_overridden_pq_upgrader_ip(
        self,
        alpha_setup_params: SetupParameters,  # pylint: disable=unused-argument
        pq_version: int,  # pylint: disable=unused-argument
        env: Environment,
        pq_upgrader_alias: Connection,  # pylint: disable=unused-argument
    ) -> None:
        client_conn, *_ = [conn.connection for conn in env.connections]
        client_alpha, *_ = env.clients

        wg_server = config.NLX_SERVER
        public_key = str(wg_server["public_key"])
        endpoint = f"{wg_server['ipv4']}:{wg_server['port']}"

        connection_config = (
            VpnConnectionConfigBuilder(public_key, endpoint)
            .force_pq()
            .with_custom_pq_upgrader_ip(self.PQ_UPGRADER_ALIAS_IP)
            .build()
        )

        await client_alpha.vpn.connect_with_config(connection_config, timeout=10)

        await ping(client_conn, config.PHOTO_ALBUM_IP)

        ip = await stun.get(client_conn, config.STUN_SERVER)
        assert (
            ip == wg_server["ipv4"]
        ), f"wrong public IP when connected to VPN with custom PQ Upgrader IP: {ip}"

    @pytest.mark.nlx
    @pytest.mark.parametrize(
        "alpha_setup_params",
        [
            pytest.param(
                SetupParameters(
                    connection_tag=ConnectionTag.DOCKER_CONE_CLIENT_1,
                    adapter_type_override=TelioAdapterType.NEP_TUN,
                    connection_tracker_config=generate_connection_tracker_config(
                        ConnectionTag.DOCKER_CONE_CLIENT_1,
                        nlx_1_limits=(2, 2),
                    ),
                    is_meshnet=False,
                ),
            ),
        ],
    )
    @pytest.mark.parametrize(
        "pq_version",
        [pytest.param(1), pytest.param(2)],
    )
    async def test_pq_vpn_rekey_with_overridden_pq_upgrader_ip(
        self,
        alpha_setup_params: SetupParameters,  # pylint: disable=unused-argument
        pq_version: int,  # pylint: disable=unused-argument
        _mutate_pq_rekey_interval: None,  # pylint: disable=unused-argument
        env: Environment,
        pq_upgrader_alias: Connection,  # pylint: disable=unused-argument
    ) -> None:
        client_conn, *_ = [conn.connection for conn in env.connections]
        client_alpha, *_ = env.clients

        wg_server = config.NLX_SERVER
        public_key = str(wg_server["public_key"])
        endpoint = f"{wg_server['ipv4']}:{wg_server['port']}"

        connection_config = (
            VpnConnectionConfigBuilder(public_key, endpoint)
            .force_pq()
            .with_custom_pq_upgrader_ip(self.PQ_UPGRADER_ALIAS_IP)
            .build()
        )

        await client_alpha.vpn.connect_with_config(connection_config, timeout=10)

        async with new_connection_by_tag(ConnectionTag.VM_LINUX_NLX_1) as nlx_conn:
            preshared_before = await inspect_preshared_key(nlx_conn)
            await client_alpha.log.wait_for("Successful PQ REKEY", incremental=True)
            preshared_after = await inspect_preshared_key(nlx_conn)
            assert (
                preshared_after != preshared_before
            ), "Preshared key not changed on the nlx server after rekey with custom IP"

        await ping(client_conn, config.PHOTO_ALBUM_IP)
        ip = await stun.get(client_conn, config.STUN_SERVER)
        assert (
            ip == wg_server["ipv4"]
        ), f"wrong public IP after rekey with custom PQ Upgrader IP: {ip}"
