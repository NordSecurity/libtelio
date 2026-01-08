import asyncio
import json
import pytest
import shlex
from contextlib import AsyncExitStack
from tests.config import DERP_SERVERS
from tests.mesh_api import API
from tests.telio import Client
from tests.utils import testing
from tests.utils.bindings import (
    features_with_endpoint_providers,
    EndpointProvider,
    Config,
    Peer,
    Server,
    TelioAdapterType,
    RelayState,
    NodeState,
)
from tests.utils.connection import ConnectionTag
from tests.utils.connection_util import (
    generate_connection_tracker_config,
    new_connection_with_conn_tracker,
)
from tests.utils.logger import log
from tests.utils.output_notifier import OutputNotifier
from tests.utils.ping import ping
from tests.utils.router import IPProto, IPStack, new_router
from tests.utils.testing import log_test_passed
from typing import Any, List, Dict

STUN_PROVIDER = [EndpointProvider.STUN]

UHP_conn_client_types = [
    (
        STUN_PROVIDER,
        ConnectionTag.DOCKER_CONE_CLIENT_1,
        ConnectionTag.DOCKER_CONE_CLIENT_2,
        TelioAdapterType.NEP_TUN,
    ),
]


def backport_config(cfg: Config) -> str:
    def backport_peer(peer: Peer) -> Dict[str, Any]:
        return {
            "identifier": peer.base.identifier,
            "public_key": peer.base.public_key,
            "hostname": peer.base.hostname,
            "ip_addresses": peer.base.ip_addresses,
            "nickname": peer.base.nickname,
            "endpoints": None,
            "is_local": peer.is_local,
            "allow_connections": peer.allow_incoming_connections,
            "allow_incoming_connections": peer.allow_incoming_connections,
            "allow_peer_send_files": peer.allow_peer_send_files,
        }

    def backport_derp(derp: Server) -> Dict[str, Any]:
        return {
            "region_code": derp.region_code,
            "name": derp.name,
            "hostname": derp.hostname,
            "ipv4": derp.ipv4,
            "relay_port": derp.relay_port,
            "stun_port": derp.stun_port,
            "stun_plaintext_port": derp.stun_plaintext_port,
            "public_key": derp.public_key,
            "weight": derp.weight,
            "use_plain_text": derp.use_plain_text,
        }

    peers: List[Dict[str, Any]] = list(
        map(backport_peer, cfg.peers if cfg.peers is not None else [])
    )
    derp_servers: List[Dict[str, Any]] = list(
        map(
            backport_derp,
            cfg.derp_servers if cfg.derp_servers is not None else DERP_SERVERS,
        )
    )

    meshmap = {
        "identifier": cfg.this.identifier,
        "public_key": cfg.this.public_key,
        "hostname": cfg.this.hostname,
        "ip_addresses": cfg.this.ip_addresses,
        "nickname": cfg.this.nickname,
        "endpoints": None,
        "peers": peers,
        "derp_servers": derp_servers,
    }

    cfg_str = json.dumps(meshmap)
    return cfg_str


# NOTE: This test can only run on natlab linux containers or on linux
# machines caintaining old tcli v3.6 "/opt/bin/tcli-3.6".
@pytest.mark.asyncio
@pytest.mark.parametrize(
    "alpha_ip_stack",
    [
        pytest.param(
            IPStack.IPv4,
            marks=pytest.mark.ipv4,
        ),
        pytest.param(
            IPStack.IPv4v6,
            marks=pytest.mark.ipv4v6,
        ),
    ],
)
@pytest.mark.parametrize(
    "endpoint_providers, client1_type, client2_type, adapter_type",
    UHP_conn_client_types,
)
async def test_connect_different_telio_version_through_relay(
    endpoint_providers,
    client1_type,
    client2_type,
    adapter_type,
    alpha_ip_stack: IPStack,
) -> None:
    async with AsyncExitStack() as exit_stack:
        api = API()

        (alpha, beta) = api.default_config_two_nodes(
            alpha_ip_stack=alpha_ip_stack, beta_ip_stack=IPStack.IPv4
        )

        (
            alpha_conn,
            alpha_conn_tracker,
        ) = await exit_stack.enter_async_context(
            new_connection_with_conn_tracker(
                client1_type,
                generate_connection_tracker_config(
                    client1_type,
                    derp_1_limits=(1, 1),
                ),
            )
        )

        (
            beta_conn,
            beta_conn_tracker,
        ) = await exit_stack.enter_async_context(
            new_connection_with_conn_tracker(
                client2_type,
                generate_connection_tracker_config(
                    client2_type,
                    derp_1_limits=(1, 1),
                ),
            )
        )

        alpha_client = await exit_stack.enter_async_context(
            Client(
                alpha_conn,
                alpha,
                adapter_type,
                telio_features=features_with_endpoint_providers(endpoint_providers),
            ).run(api.get_meshnet_config(alpha.id))
        )

        output_notifier = OutputNotifier()
        started_event = asyncio.Event()
        output_notifier.notify_output("started telio with BoringTun", started_event)

        async def on_stdout_stderr(output):
            log.info("[%s]: stdout: %s", beta.name, output)
            await output_notifier.handle_output(output)

        beta_router = new_router(beta_conn, beta.ip_stack)
        beta_client_v3_6 = await exit_stack.enter_async_context(
            beta_conn.create_process([
                "/opt/bin/tcli-3.6",
                "--less-spam",
                '-f { "paths": { "priority": ["relay", "udp-hole-punch"]} }',
            ]).run(on_stdout_stderr, on_stdout_stderr)
        )
        await beta_client_v3_6.wait_stdin_ready()
        await beta_client_v3_6.escape_and_write_stdin(
            ["dev", "start", "boringtun", "tun10", str(beta.private_key)]
        )
        await started_event.wait()
        await beta_router.setup_interface(beta.ip_addresses)
        await beta_router.create_meshnet_route()

        await beta_client_v3_6.escape_and_write_stdin([
            "mesh",
            "config",
            shlex.quote(backport_config(api.get_meshnet_config(beta.id))),
        ])

        await alpha_client.wait_for_state_on_any_derp([RelayState.CONNECTED])
        await alpha_client.wait_for_state_peer(beta.public_key, [NodeState.CONNECTED])

        await ping(
            alpha_conn,
            testing.unpack_optional(beta.get_ip_address(IPProto.IPv4)),
        )

        assert await alpha_conn_tracker.find_conntracker_violations() is None
        assert await beta_conn_tracker.find_conntracker_violations() is None
        log_test_passed()
