import asyncio
import pytest
from collections.abc import AsyncIterator, Callable, Sequence
from contextlib import AsyncExitStack, asynccontextmanager
from dataclasses import dataclass
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
from tests.utils.logger import log
from tests.utils.ping import Ping, ping
from tests.utils.python import get_python_binary
from tests.utils.router import IPStack
from typing import Optional

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
PQ_REKEY_FAILED_LOG = "Failed to perform PQ rekey"
PQ_RESTART_LOG = "Restarting postquantum entity"
# WireGuard whitepaper 6.1: the initiator starts a new handshake when it sends data
# over a session older than this.
WG_REKEY_AFTER_TIME_S = 120
# WireGuard whitepaper 6.1: an unanswered handshake initiation is retried after this.
WG_REKEY_TIMEOUT_S = 5
# Short, so that a few PQ rekeys fit in the healthy-tunnel timing test.
HEALTHY_PQ_REKEY_INTERVAL_S = 10
HEALTHY_PQ_REKEY_COUNT = 3
# Leaves time to block the PQ upgrader before the first rekey attempt.
FAILED_PQ_REKEY_INTERVAL_S = 20
# Fits several times into WireGuard's 120s rekey cycle: the fixed timer rekeys a few
# times per WireGuard handshake, the new mode once, at the 30s mark.
KERNEL_WG_PQ_REKEY_INTERVAL_S = 30
# Allowed delay between "rekey_interval_s since the last handshake" and seeing the new
# preshared key on the server: libtelio polls WireGuard every second, nlx reports
# handshakes with 1s resolution, plus the rekey round trip and our sampling period.
PQ_REKEY_SLACK_S = 4
# REJECT_AFTER_TIME in telio-pq: a PQ session that can't rekey for this long is
# restarted from scratch.
PQ_SESSION_TIMEOUT_S = 180
# The restart check runs on libtelio's 5s WireGuard consolidation tick, and the client
# log is polled every second.
PQ_RESTART_DETECTION_SLACK_S = 10
NLX_SAMPLING_PERIOD_S = 0.5
PQ_REKEY_MODES = [
    pytest.param(True, id="rekey_after_wg_handshake"),
    pytest.param(False, id="rekey_on_fixed_timer"),
]
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
    def _mutate_pq_rekey(self, alpha_setup_params: SetupParameters, pq_version: int, rekey_attached_to_wg_handshake: bool):
        alpha_setup_params.features.post_quantum_vpn.rekey_interval_s = (
            # SHORT_PQ_REKEY_INTERVAL_S
            30
        )
        alpha_setup_params.features.post_quantum_vpn.version = pq_version
        alpha_setup_params.features.post_quantum_vpn.rekey_attached_to_wg_handshake = rekey_attached_to_wg_handshake

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
    @pytest.mark.parametrize(
        "rekey_attached_to_wg_handshake",
        [True,False],
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

        client_log = (await client_alpha.log.get()).lower()
        log_line = PQ_RESTART_LOG.lower()
        occurrences = client_log.count(log_line)

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
        await nlx_conn.create_process(
            [
                "ip",
                "addr",
                "replace",
                f"{self.PQ_UPGRADER_ALIAS_IP}/32",
                "dev",
                "nlx0",
            ]
        ).execute()
        await nlx_conn.create_process(
            [
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
            ]
        ).execute()

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

        await client_alpha.vpn.connect_with_config(
            public_key, connection_config, timeout=10
        )

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

        await client_alpha.vpn.connect_with_config(
            public_key, connection_config, timeout=10
        )

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


@dataclass(frozen=True)
class PqRekey:
    """A new preshared key showed up for the client's peer on the NLX server."""

    # NLX clock (unix seconds): when the new key was first seen
    at: float
    # NLX clock (unix seconds): the latest WireGuard handshake while the old key was
    # still in place
    last_wg_handshake: int

    @property
    def since_wg_handshake(self) -> float:
        return self.at - self.last_wg_handshake


async def _read_nlx_peers(
    nlx_conn: Connection,
) -> tuple[float, dict[str, tuple[str, int]]]:
    """NLX server time and {public key: (preshared key, latest handshake)} of its peers.

    `nlx show <iface> dump` uses the `wg show <iface> dump` format: one interface line,
    then per peer: public-key preshared-key endpoint allowed-ips latest-handshake
    transfer-rx transfer-tx persistent-keepalive.
    """
    process = await nlx_conn.create_process(
        ["bash", "-c", f"date +%s.%N && nlx show {NLX_INTERFACE} dump"],
        quiet=True,
    ).execute()
    now, _interface, *peer_lines = process.get_stdout().splitlines()
    peers: dict[str, tuple[str, int]] = {}
    for line in peer_lines:
        public_key, preshared_key, _endpoint, _ips, latest_handshake, *_ = line.split()
        peers[public_key] = (preshared_key, int(latest_handshake))
    return float(now), peers


async def _find_pq_client_public_key(nlx_conn: Connection) -> str:
    """Public key of the PQ client that has just connected, as known to NLX.

    A PQ session uses a freshly generated WireGuard key, not the node's own key, so
    take the PQ peer that handshaked most recently.
    """
    _, peers = await _read_nlx_peers(nlx_conn)
    pq_peers = {
        public_key: latest_handshake
        for public_key, (preshared_key, latest_handshake) in peers.items()
        if preshared_key != EMPTY_PRESHARED_KEY_SLOT
    }
    assert pq_peers, f"no peer with a preshared key on {NLX_INTERFACE}"
    return max(pq_peers, key=lambda public_key: pq_peers[public_key])


class NlxPeerObserver:
    """Records WireGuard handshakes and preshared key changes of one NLX peer.

    nlx only reports the latest handshake and the current preshared key, so the peer
    is sampled every NLX_SAMPLING_PERIOD_S. Events in these tests are >= 10s apart.
    """

    def __init__(self, nlx_conn: Connection, public_key: str) -> None:
        self._nlx_conn = nlx_conn
        self._public_key = public_key
        self._preshared_key: Optional[str] = None
        self._sampler: Optional[asyncio.Task] = None
        self.wg_handshakes: list[int] = []
        self.pq_rekeys: list[PqRekey] = []
        # NLX clock (unix seconds) of the most recent sample
        self.last_sample_at = 0.0

    async def _sample(self) -> None:
        now, peers = await _read_nlx_peers(self._nlx_conn)
        self.last_sample_at = now
        assert self._public_key in peers, f"peer {self._public_key} left NLX"
        preshared_key, latest_handshake = peers[self._public_key]

        if self._preshared_key is not None and preshared_key != self._preshared_key:
            # Use the handshake from the previous sample: with neptun the new key
            # triggers a handshake right away, which may already be in this sample.
            assert self.wg_handshakes, "preshared key changed before any handshake"
            self.pq_rekeys.append(PqRekey(now, self.wg_handshakes[-1]))
        self._preshared_key = preshared_key

        if latest_handshake and latest_handshake not in self.wg_handshakes[-1:]:
            self.wg_handshakes.append(latest_handshake)

    @asynccontextmanager
    async def observe(self) -> AsyncIterator["NlxPeerObserver"]:
        await self._sample()
        stop = asyncio.Event()

        async def sample_until_stopped() -> None:
            while not stop.is_set():
                await asyncio.sleep(NLX_SAMPLING_PERIOD_S)
                await self._sample()

        self._sampler = asyncio.create_task(sample_until_stopped())
        try:
            yield self
        finally:
            stop.set()
            await asyncio.gather(self._sampler, return_exceptions=True)

    async def wait_until(
        self, condition: Callable[[], bool], timeout: float, what: str
    ) -> None:
        try:
            async with asyncio.timeout(timeout):
                while not condition():
                    if self._sampler is not None and self._sampler.done():
                        self._sampler.result()  # re-raise what stopped the sampler
                    await asyncio.sleep(NLX_SAMPLING_PERIOD_S)
        except TimeoutError as e:
            raise AssertionError(
                f"no {what} within {timeout}s, timeline:\n{self.timeline()}"
            ) from e

    def timeline(self, extra_events: Sequence[tuple[float, str]] = ()) -> str:
        """Human-readable history, relative to the first observed handshake.

        `extra_events` are (NLX clock, description) pairs to show alongside.
        """
        if not self.wg_handshakes:
            return "  (no WireGuard handshakes)"
        start = self.wg_handshakes[0]
        events = [(float(t), "WireGuard handshake") for t in self.wg_handshakes]
        events += [
            (
                rekey.at,
                "new preshared key (PQ rekey),"
                f" {rekey.since_wg_handshake:.1f}s after the last WireGuard handshake",
            )
            for rekey in self.pq_rekeys
        ]
        events += extra_events
        return "\n".join(f"  +{at - start:6.1f}s {what}" for at, what in sorted(events))


def _pq_rekey_timing_setup_params(adapter: TelioAdapterType) -> SetupParameters:
    return SetupParameters(
        connection_tag=ConnectionTag.DOCKER_CONE_CLIENT_1,
        adapter_type_override=adapter,
        connection_tracker_config=generate_connection_tracker_config(
            ConnectionTag.DOCKER_CONE_CLIENT_1,
            nlx_1_limits=(2, 2),
        ),
        is_meshnet=False,
    )


class TestPqRekeyTiming:
    """PQ rekey timing relative to WireGuard handshakes (LLT-6292).

    `post_quantum_vpn.rekey_attached_to_wg_handshake` changes what starts a PQ rekey:

    * False (old behaviour): a fixed timer - `rekey_interval_s` after the PQ keys were
      fetched and every `rekey_interval_s` after that. WireGuard handshakes are
      ignored.
    * True (new behaviour): `rekey_interval_s` after the most recent WireGuard
      handshake with the VPN server, at most once per handshake.

    In a healthy neptun tunnel the two look the same: a new preshared key drops
    neptun's sessions, so every PQ rekey immediately causes a WireGuard handshake,
    which re-arms the next PQ rekey. A failed PQ rekey is retried on a timer in both
    modes, so failures don't set them apart either. They only differ when WireGuard
    handshakes for some other reason - e.g. with kernel WireGuard a new preshared key
    doesn't trigger a handshake, so the new mode waits for WireGuard's own rekey
    (REKEY_AFTER_TIME, 120s) before the next PQ rekey.

    The new mode also changes when a PQ session that can't rekey is restarted:
    180s after the first WireGuard handshake following the last PQ key exchange
    (RFC LLT-0120), instead of 180s after the key exchange itself.

    Everything is measured on the NLX server (`nlx show nlx0 dump`) with the server's
    clock, so the tests don't depend on the client's WireGuard implementation or logs.
    """

    @pytest.fixture(autouse=True)
    def _mutate_pq_features(
        self,
        alpha_setup_params: SetupParameters,
        pq_version: int,
        rekey_interval_s: int,
        rekey_attached_to_wg_handshake: bool,
    ) -> None:
        pq = alpha_setup_params.features.post_quantum_vpn
        pq.version = pq_version
        pq.rekey_interval_s = rekey_interval_s
        pq.handshake_retry_interval_s = PQ_HANDSHAKE_RETRY_INTERVAL_S
        pq.rekey_attached_to_wg_handshake = rekey_attached_to_wg_handshake

    @pytest.mark.nlx
    @pytest.mark.parametrize(
        "alpha_setup_params",
        [pytest.param(_pq_rekey_timing_setup_params(TelioAdapterType.NEP_TUN))],
    )
    @pytest.mark.parametrize("pq_version", PQ_VERSIONS)
    @pytest.mark.parametrize("rekey_interval_s", [HEALTHY_PQ_REKEY_INTERVAL_S])
    @pytest.mark.parametrize("rekey_attached_to_wg_handshake", PQ_REKEY_MODES)
    async def test_pq_rekey_cadence_in_healthy_neptun_tunnel(
        self,
        alpha_setup_params: SetupParameters,  # pylint: disable=unused-argument
        pq_version: int,  # pylint: disable=unused-argument
        rekey_interval_s: int,
        rekey_attached_to_wg_handshake: bool,  # pylint: disable=unused-argument
        env: Environment,
    ) -> None:
        """Both modes: one PQ rekey `rekey_interval_s` after every WireGuard handshake.

        neptun drops its sessions when the preshared key changes, so each PQ rekey
        causes the next handshake. The old fixed timer therefore lines up with the
        handshakes, and the new mode has to re-arm after every one of them.
        """
        client_conn, *_ = [conn.connection for conn in env.connections]
        client, *_ = env.clients

        await _connect_vpn_pq(client_conn, client)

        async with new_connection_by_tag(ConnectionTag.VM_LINUX_NLX_1) as nlx_conn:
            nlx = NlxPeerObserver(nlx_conn, await _find_pq_client_public_key(nlx_conn))
            async with nlx.observe():
                await nlx.wait_until(
                    lambda: len(nlx.pq_rekeys) >= HEALTHY_PQ_REKEY_COUNT,
                    timeout=HEALTHY_PQ_REKEY_COUNT
                    * (rekey_interval_s + PQ_REKEY_SLACK_S)
                    + 10,
                    what=f"{HEALTHY_PQ_REKEY_COUNT} PQ rekeys",
                )

        timeline = nlx.timeline()
        log.info("PQ rekey timeline:\n%s", timeline)

        for rekey in nlx.pq_rekeys:
            assert (
                rekey_interval_s - 1
                <= rekey.since_wg_handshake
                <= rekey_interval_s + PQ_REKEY_SLACK_S
            ), f"PQ rekey not {rekey_interval_s}s after a handshake:\n{timeline}"
        anchors = [rekey.last_wg_handshake for rekey in nlx.pq_rekeys]
        assert len(set(anchors)) == len(
            anchors
        ), f"more than one PQ rekey per WireGuard handshake:\n{timeline}"

        await ping(client_conn, config.PHOTO_ALBUM_IP)

    @pytest.mark.nlx
    @pytest.mark.timeout(300)
    @pytest.mark.parametrize(
        "alpha_setup_params",
        [
            pytest.param(
                _pq_rekey_timing_setup_params(TelioAdapterType.LINUX_NATIVE_TUN),
                marks=pytest.mark.linux_native,
            ),
        ],
    )
    @pytest.mark.parametrize("pq_version", [PQ_VERSION_V2])
    @pytest.mark.parametrize("rekey_interval_s", [KERNEL_WG_PQ_REKEY_INTERVAL_S])
    @pytest.mark.parametrize("rekey_attached_to_wg_handshake", PQ_REKEY_MODES)
    async def test_pq_rekey_cadence_in_healthy_kernel_wg_tunnel(
        self,
        alpha_setup_params: SetupParameters,  # pylint: disable=unused-argument
        pq_version: int,  # pylint: disable=unused-argument
        rekey_interval_s: int,
        rekey_attached_to_wg_handshake: bool,
        env: Environment,
    ) -> None:
        """Kernel WireGuard: the two modes differ even in a healthy tunnel.

        Kernel WireGuard updates the preshared key in place, so a PQ rekey doesn't
        cause a handshake - handshakes only come from WireGuard's own rekey, every
        REKEY_AFTER_TIME (120s).
        New: one PQ rekey per WireGuard handshake, `rekey_interval_s` after it.
        Old: a PQ rekey every `rekey_interval_s`, several per WireGuard handshake.
        """
        client_conn, *_ = [conn.connection for conn in env.connections]
        client, *_ = env.clients

        await _connect_vpn_pq(client_conn, client)

        async with AsyncExitStack() as exit_stack:
            nlx_conn = await exit_stack.enter_async_context(
                new_connection_by_tag(ConnectionTag.VM_LINUX_NLX_1)
            )
            nlx = NlxPeerObserver(nlx_conn, await _find_pq_client_public_key(nlx_conn))
            await exit_stack.enter_async_context(nlx.observe())
            connected_handshake = nlx.wg_handshakes[0]

            # Keep data flowing, so that WireGuard rekeys right at REKEY_AFTER_TIME.
            await exit_stack.enter_async_context(
                Ping(client_conn, config.PHOTO_ALBUM_IP).run()
            )

            # One full WireGuard cycle, plus the PQ rekey that should follow the
            # second handshake in the new mode. That handshake may need one retry,
            # e.g. when it collides with a PQ rekey in the old mode.
            window_s = (
                WG_REKEY_AFTER_TIME_S
                + WG_REKEY_TIMEOUT_S
                + rekey_interval_s
                + PQ_REKEY_SLACK_S
            )
            await nlx.wait_until(
                lambda: nlx.last_sample_at >= connected_handshake + window_s,
                timeout=window_s + 30,
                what="end of the observation window",
            )

        handshakes = nlx.wg_handshakes
        anchors = [rekey.last_wg_handshake for rekey in nlx.pq_rekeys]
        timeline = nlx.timeline()
        log.info("PQ rekey timeline:\n%s", timeline)

        assert (
            len(handshakes) == 2
        ), f"expected only the connect handshake and WireGuard's own rekey:\n{timeline}"

        if rekey_attached_to_wg_handshake:
            assert (
                anchors == handshakes
            ), f"expected exactly one PQ rekey per WireGuard handshake:\n{timeline}"
            for rekey in nlx.pq_rekeys:
                assert (
                    rekey_interval_s - 1
                    <= rekey.since_wg_handshake
                    <= rekey_interval_s + PQ_REKEY_SLACK_S
                ), f"PQ rekey not {rekey_interval_s}s after a handshake:\n{timeline}"
        else:
            assert len(set(anchors)) < len(
                anchors
            ), f"expected several PQ rekeys per WireGuard handshake:\n{timeline}"
            for previous, current in zip(nlx.pq_rekeys, nlx.pq_rekeys[1:]):
                assert (
                    abs(current.at - previous.at - rekey_interval_s) <= 2
                ), f"PQ rekeys not {rekey_interval_s}s apart:\n{timeline}"

        await ping(client_conn, config.PHOTO_ALBUM_IP)

    @pytest.mark.nlx
    @pytest.mark.timeout(300)
    @pytest.mark.parametrize(
        "alpha_setup_params",
        [
            pytest.param(_pq_rekey_timing_setup_params(TelioAdapterType.NEP_TUN)),
            pytest.param(
                _pq_rekey_timing_setup_params(TelioAdapterType.LINUX_NATIVE_TUN),
                marks=pytest.mark.linux_native,
            ),
        ],
    )
    @pytest.mark.parametrize("pq_version", [PQ_VERSION_V2])
    @pytest.mark.parametrize("rekey_interval_s", [FAILED_PQ_REKEY_INTERVAL_S])
    @pytest.mark.parametrize("rekey_attached_to_wg_handshake", PQ_REKEY_MODES)
    async def test_pq_rekey_after_failed_rekey(
        self,
        alpha_setup_params: SetupParameters,  # pylint: disable=unused-argument
        pq_version: int,  # pylint: disable=unused-argument
        rekey_interval_s: int,
        rekey_attached_to_wg_handshake: bool,  # pylint: disable=unused-argument
        env: Environment,
    ) -> None:
        """A failed PQ rekey is retried every `handshake_retry_interval_s`, in both modes.

        With `rekey_attached_to_wg_handshake` the retries are still timer driven and
        don't wait for the next WireGuard handshake. So in both modes the successful
        rekey comes long before WireGuard's own rekey, still anchored to the
        handshake made when connecting.
        """
        client_conn, *_ = [conn.connection for conn in env.connections]
        client, *_ = env.clients

        await _connect_vpn_pq(client_conn, client)

        async with AsyncExitStack() as exit_stack:
            nlx_conn = await exit_stack.enter_async_context(
                new_connection_by_tag(ConnectionTag.VM_LINUX_NLX_1)
            )
            nlx = NlxPeerObserver(nlx_conn, await _find_pq_client_public_key(nlx_conn))
            await exit_stack.enter_async_context(nlx.observe())
            connected_handshake = nlx.wg_handshakes[0]

            # Keep data flowing: if the rekey isn't retried, WireGuard then rekeys on
            # its own after REKEY_AFTER_TIME and that shows up in the timeline
            # (neptun doesn't count keepalives as data).
            await exit_stack.enter_async_context(
                Ping(client_conn, config.PHOTO_ALBUM_IP).run()
            )

            # Like a client that routes the PQ upgrader outside of the tunnel:
            # PQ rekeys fail, WireGuard traffic is unaffected.
            async with client.get_router().break_udp_conn_to_host(PQ_UPGRADER_IP):
                await asyncio.wait_for(
                    client.log.wait_for(PQ_REKEY_FAILED_LOG, incremental=True),
                    rekey_interval_s + PQ_HANDSHAKE_RETRY_INTERVAL_S + 15,
                )

            await nlx.wait_until(
                lambda: bool(nlx.pq_rekeys),
                timeout=WG_REKEY_AFTER_TIME_S + rekey_interval_s + 30,
                what="successful PQ rekey",
            )

        rekey = nlx.pq_rekeys[0]
        timeline = nlx.timeline()
        log.info("PQ rekey timeline:\n%s", timeline)

        # First attempt at ~rekey_interval_s, then a retry every
        # PQ_HANDSHAKE_RETRY_INTERVAL_S. Allow one extra retry in case the upgrader
        # got unblocked only after the first one.
        retried_within = (
            rekey_interval_s + 2 * PQ_HANDSHAKE_RETRY_INTERVAL_S + PQ_REKEY_SLACK_S
        )
        assert (
            rekey.last_wg_handshake == connected_handshake
        ), f"PQ rekey waited for a WireGuard handshake instead of retrying:\n{timeline}"
        assert (
            rekey.since_wg_handshake <= retried_within
        ), f"failed PQ rekey not retried within {retried_within}s:\n{timeline}"

        await ping(client_conn, config.PHOTO_ALBUM_IP)

    @pytest.mark.nlx
    @pytest.mark.timeout(420)
    @pytest.mark.parametrize(
        "alpha_setup_params",
        [
            pytest.param(
                _pq_rekey_timing_setup_params(TelioAdapterType.LINUX_NATIVE_TUN),
                marks=pytest.mark.linux_native,
            ),
        ],
    )
    @pytest.mark.parametrize("pq_version", [PQ_VERSION_V2])
    @pytest.mark.parametrize("rekey_interval_s", [KERNEL_WG_PQ_REKEY_INTERVAL_S])
    @pytest.mark.parametrize("rekey_attached_to_wg_handshake", PQ_REKEY_MODES)
    async def test_pq_restart_after_failed_rekeys_in_kernel_wg_tunnel(
        self,
        alpha_setup_params: SetupParameters,  # pylint: disable=unused-argument
        pq_version: int,  # pylint: disable=unused-argument
        rekey_interval_s: int,
        rekey_attached_to_wg_handshake: bool,
        env: Environment,
    ) -> None:
        """A PQ session that keeps failing to rekey is restarted after 180s.

        The modes count those 180s from different points:
        Old: the last successful PQ key exchange.
        New (RFC LLT-0120): the first WireGuard handshake after it, i.e. the start of
        the WireGuard session keyed with the latest preshared key.

        Kernel WireGuard doesn't handshake when the preshared key changes, so after the
        PQ rekey at +30s the next session starts only with WireGuard's own rekey at
        +120s: the restart comes at about +210s in the old mode and +300s in the new
        one. With neptun every PQ rekey causes a handshake, so the two coincide.
        """
        client_conn, *_ = [conn.connection for conn in env.connections]
        client, *_ = env.clients

        await _connect_vpn_pq(client_conn, client)

        async with AsyncExitStack() as exit_stack:
            nlx_conn = await exit_stack.enter_async_context(
                new_connection_by_tag(ConnectionTag.VM_LINUX_NLX_1)
            )
            nlx = NlxPeerObserver(nlx_conn, await _find_pq_client_public_key(nlx_conn))
            await exit_stack.enter_async_context(nlx.observe())

            # Keep data flowing, so that WireGuard rekeys right at REKEY_AFTER_TIME.
            await exit_stack.enter_async_context(
                Ping(client_conn, config.PHOTO_ALBUM_IP).run()
            )

            await nlx.wait_until(
                lambda: bool(nlx.pq_rekeys),
                timeout=rekey_interval_s + PQ_REKEY_SLACK_S + 10,
                what="PQ rekey",
            )
            key_exchange = nlx.pq_rekeys[0]

            # From now on every PQ rekey fails, while WireGuard keeps working with the
            # last preshared key.
            await exit_stack.enter_async_context(
                client.get_router().break_udp_conn_to_host(PQ_UPGRADER_IP)
            )
            try:
                await asyncio.wait_for(
                    client.log.wait_for(PQ_RESTART_LOG, incremental=True),
                    WG_REKEY_AFTER_TIME_S
                    + PQ_SESSION_TIMEOUT_S
                    + PQ_RESTART_DETECTION_SLACK_S,
                )
            except TimeoutError as e:
                raise AssertionError(
                    f"PQ session not restarted, timeline:\n{nlx.timeline()}"
                ) from e
            restarted_at = nlx.last_sample_at

        timeline = nlx.timeline([(restarted_at, "PQ session restarted")])
        log.info("PQ restart timeline:\n%s", timeline)

        sessions = [t for t in nlx.wg_handshakes if t > key_exchange.at]
        assert sessions, f"no WireGuard handshake after the PQ rekey:\n{timeline}"
        if rekey_attached_to_wg_handshake:
            anchor = float(sessions[0])
            anchor_name = "the first WireGuard handshake after the last PQ rekey"
        else:
            anchor = key_exchange.at
            anchor_name = "the last PQ rekey"
        assert (
            PQ_SESSION_TIMEOUT_S - 1
            <= restarted_at - anchor
            <= PQ_SESSION_TIMEOUT_S + PQ_RESTART_DETECTION_SLACK_S
        ), (
            f"PQ session not restarted {PQ_SESSION_TIMEOUT_S}s after {anchor_name}:"
            f"\n{timeline}"
        )

        # The restarted session recovers once the PQ upgrader is reachable again.
        await ping(client_conn, config.PHOTO_ALBUM_IP)
