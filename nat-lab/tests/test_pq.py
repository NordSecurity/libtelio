import asyncio
import pytest
from collections.abc import AsyncIterator
from datetime import datetime, timedelta
from tests import config
from tests.helpers import SetupParameters, Environment
from tests.libtelio_client import Client
from tests.uniffi.telio_bindings import VpnConnectionConfigBuilder
from tests.utils import asyncio_util, stun
from tests.utils.bindings import TelioAdapterType, NodeState, PathType
from tests.utils.connection import Connection, ConnectionTag
from tests.utils.connection_util import (
    generate_connection_tracker_config,
    new_connection_by_tag,
)
from tests.utils.dns import query_dns
from tests.utils.ping import ping
from tests.utils.router import IPStack

EMPTY_PRESHARED_KEY_SLOT = "(none)"


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
    output = await nlx_conn.create_process(["nlx", "show", "nlx0", "dump"]).execute()
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
        [pytest.param(1), pytest.param(2)],
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
        alpha_setup_params.features.post_quantum_vpn.rekey_interval_s = 2
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
        [pytest.param(1), pytest.param(2)],
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
            await client_alpha.log.wait_for("Successful PQ REKEY", incremental=True)

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
        [pytest.param(1), pytest.param(2)],
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
        alpha_setup_params.features.post_quantum_vpn.handshake_retry_interval_s = 5
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
        [pytest.param(1), pytest.param(2)],
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
        [pytest.param(1), pytest.param(2)],
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
            log_line = "Restarting postquantum entity".lower()
            occurrences = client_log.count(log_line)

            assert (
                occurrences == 0
            ), "Found PQ restart log even though PQ should not have been restarted yet"

            await client_alpha.log.wait_for("Restarting postquantum entity")

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
        log_line = "Restarting postquantum entity".lower()
        occurrences = log.count(log_line)

        assert (
            occurrences == 0
        ), "Found PQ restart log even though PQ should not have been restarted"


class TestCustomPqUpgraderIp:
    """Verify that with_custom_pq_upgrader_ip pointing to an alias IP (10.5.1.1) which
    is DNAT-redirected to the real PQ upgrader (10.5.0.1) still establishes a working
    PQ VPN connection. This proves the parameter flows end-to-end through the stack
    using a genuinely different IP from the default.

    The PQ upgrader service is reachable at 10.5.0.1 inside the VPN tunnel.
    To test with_custom_pq_upgrader_ip using a genuinely *different* address, we add a
    secondary IP alias on the NLX container's WireGuard interface and install a
    DNAT rule that redirects PQ-upgrader traffic arriving at the alias back to the
    real upgrader port. The client then uses the alias as the custom PQ Upgrader IP."""

    PQ_UPGRADER_REAL_IP = "10.5.0.1"
    PQ_UPGRADER_ALIAS_IP = "10.5.1.1"  # alias used only by this test
    PQ_UPGRADER_PORT = 6480

    async def _add_pq_upgrader_alias(self, nlx_conn: Connection) -> None:
        """Add an IP alias and DNAT rule on the NLX WireGuard interface so that
        PQ-upgrader traffic sent to PQ_UPGRADER_ALIAS_IP is forwarded to the real
        upgrader at PQ_UPGRADER_REAL_IP."""
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
        """Remove the IP alias and DNAT rule added by _add_pq_upgrader_alias.

        Each command is run with '|| true' so removal is idempotent — safe to call
        even when setup failed partway through."""
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
        """Fixture that adds the PQ upgrader IP alias and DNAT rule before the test
        and guarantees removal afterwards, even on test failure or cancellation.

        The try/finally guards partial-setup failure: _remove_pq_upgrader_alias runs
        even when _add_pq_upgrader_alias raises partway through (e.g. ip-addr replace
        succeeds but iptables -A fails), preventing alias leakage onto nlx0."""
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
        """Connect with override PQ upgrader IP set to an alias IP (10.5.1.1) that is
        distinct from the default 10.5.0.1. A DNAT rule on the NLX WireGuard interface
        redirects traffic destined for the alias back to the real PQ upgrader, so the
        connection must succeed exactly as with the default IP. This validates that the
        override is correctly threaded from the builder all the way to
        proto::fetch_keys() and proto::rekey()."""
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

        await client_alpha.configure_interface()
        await client_alpha.get_router().create_vpn_route()
        client_alpha.get_runtime().allowed_pub_keys.add(public_key)

        async with asyncio_util.run_async_context(
            client_alpha.events.wait_for_event_peer(
                public_key,
                [NodeState.CONNECTED],
                list(PathType),
                is_exit=True,
                is_vpn=True,
                timeout=10,
            )
        ) as event:
            await client_alpha.get_proxy().connect_to_exit_node_with_config(
                connection_config
            )
            await event

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
        """Verify that PQ rekey succeeds when with_custom_pq_upgrader_ip is set to an
        alias IP (10.5.1.1) DNAT-redirected to the real upgrader (10.5.0.1). After the
        initial connection, a fast rekey is triggered (rekey_interval_s=2). The
        preshared key on the NLX server must rotate and connectivity must be maintained
        post-rekey. This proves the custom IP override is threaded through both
        proto::fetch_keys() and proto::rekey()."""
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

        await client_alpha.configure_interface()
        await client_alpha.get_router().create_vpn_route()
        client_alpha.get_runtime().allowed_pub_keys.add(public_key)

        async with asyncio_util.run_async_context(
            client_alpha.events.wait_for_event_peer(
                public_key,
                [NodeState.CONNECTED],
                list(PathType),
                is_exit=True,
                is_vpn=True,
                timeout=10,
            )
        ) as event:
            await client_alpha.get_proxy().connect_to_exit_node_with_config(
                connection_config
            )
            await event

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
