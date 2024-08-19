import asyncio
import json
import pytest
import shlex
from contextlib import AsyncExitStack
from mesh_api import API
from telio import Client
from utils import testing
from utils.bindings import (
    features_with_endpoint_providers,
    EndpointProvider,
    TelioAdapterType,
    NodeState,
    RelayState,
    Config,
)
from utils.connection_util import (
    ConnectionTag,
    ConnectionLimits,
    generate_connection_tracker_config,
    new_connection_with_conn_tracker,
)
from utils.output_notifier import OutputNotifier
from utils.ping import ping
from utils.router import IPProto, IPStack, new_router

STUN_PROVIDER = [EndpointProvider.STUN]

UHP_conn_client_types = [
    (
        STUN_PROVIDER,
        ConnectionTag.DOCKER_CONE_CLIENT_1,
        ConnectionTag.DOCKER_CONE_CLIENT_2,
        TelioAdapterType.BORING_TUN,
    ),
]


def serialize_config(cfg: Config) -> str:
    cfg_dict = cfg.this.__dict__

    peers = []
    if cfg.peers is not None:
        for peer in cfg.peers:
            peer_dict = {**peer.__dict__, **peer.base.__dict__}
            del peer_dict["base"]

    derp = []
    if cfg.derp_servers is not None:
        for server in cfg.derp_servers:
            derp_dict = server.__dict__
            derp_dict["conn_state"] = derp_dict["conn_state"].name.lower()
            derp.append(derp_dict)
    
    cfg_dict["peers"] = peers 
    cfg_dict["derp_servers"] = derp

    cfg_str = json.dumps(cfg_dict)
    print(f"Serialized cfg {cfg_str}")
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
                    derp_1_limits=ConnectionLimits(1, 1),
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
                    derp_1_limits=ConnectionLimits(1, 1),
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
            print(f"[{beta.name}]: stdout: {output}")
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
            shlex.quote(serialize_config(api.get_meshnet_config(beta.id))),
        ])

        await alpha_client.wait_for_state_on_any_derp([RelayState.CONNECTED])
        await alpha_client.wait_for_state_peer(beta.public_key, [NodeState.CONNECTED])

        await ping(
            alpha_conn,
            testing.unpack_optional(beta.get_ip_address(IPProto.IPv4)),
        )

        assert alpha_conn_tracker.get_out_of_limits() is None
        assert beta_conn_tracker.get_out_of_limits() is None
