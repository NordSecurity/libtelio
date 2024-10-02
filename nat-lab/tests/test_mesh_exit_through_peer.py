import asyncio
import config
import pytest
from contextlib import AsyncExitStack
from helpers import setup_mesh_nodes, SetupParameters
from mesh_api import API
from telio import Client
from utils import testing, stun
from utils.bindings import PathType, NodeState, RelayState, TelioAdapterType
from utils.connection_tracker import ConnectionLimits
from utils.connection_util import (
    generate_connection_tracker_config,
    ConnectionTag,
    new_connection_with_conn_tracker,
)
from utils.ping import ping
from utils.router import IPProto, IPStack


# Marks in-tunnel stack only, exiting only through IPv4
@pytest.mark.asyncio
@pytest.mark.parametrize(
    "exit_ip_stack",
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
    "alpha_setup_params",
    [
        pytest.param(
            SetupParameters(
                connection_tag=ConnectionTag.DOCKER_CONE_CLIENT_1,
                ip_stack=IPStack.IPv4v6,
                adapter_type_override=TelioAdapterType.BORING_TUN,
                connection_tracker_config=generate_connection_tracker_config(
                    ConnectionTag.DOCKER_CONE_CLIENT_1,
                    derp_1_limits=ConnectionLimits(1, 1),
                ),
            )
        ),
        pytest.param(
            SetupParameters(
                connection_tag=ConnectionTag.DOCKER_CONE_CLIENT_1,
                ip_stack=IPStack.IPv4v6,
                adapter_type_override=TelioAdapterType.LINUX_NATIVE_TUN,
                connection_tracker_config=generate_connection_tracker_config(
                    ConnectionTag.DOCKER_CONE_CLIENT_1,
                    derp_1_limits=ConnectionLimits(1, 1),
                ),
            ),
            marks=pytest.mark.linux_native,
        ),
        pytest.param(
            SetupParameters(
                connection_tag=ConnectionTag.WINDOWS_VM_1,
                ip_stack=IPStack.IPv4v6,
                adapter_type_override=TelioAdapterType.WINDOWS_NATIVE_TUN,
                connection_tracker_config=generate_connection_tracker_config(
                    ConnectionTag.WINDOWS_VM_1,
                    derp_1_limits=ConnectionLimits(1, 1),
                ),
            ),
            marks=pytest.mark.windows,
        ),
        pytest.param(
            SetupParameters(
                connection_tag=ConnectionTag.WINDOWS_VM_1,
                ip_stack=IPStack.IPv4v6,
                adapter_type_override=TelioAdapterType.WIREGUARD_GO_TUN,
                connection_tracker_config=generate_connection_tracker_config(
                    ConnectionTag.WINDOWS_VM_1,
                    derp_1_limits=ConnectionLimits(1, 1),
                ),
            ),
            marks=pytest.mark.windows,
        ),
        pytest.param(
            SetupParameters(
                connection_tag=ConnectionTag.MAC_VM,
                ip_stack=IPStack.IPv4v6,
                adapter_type_override=TelioAdapterType.BORING_TUN,
                connection_tracker_config=generate_connection_tracker_config(
                    ConnectionTag.MAC_VM,
                    derp_1_limits=ConnectionLimits(1, 1),
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
                    derp_1_limits=ConnectionLimits(1, 1),
                    stun_limits=ConnectionLimits(1, 2),
                ),
            )
        )
    ],
)
async def test_mesh_exit_through_peer(
    alpha_setup_params: SetupParameters,
    beta_setup_params: SetupParameters,
    exit_ip_stack: IPStack,
) -> None:
    async with AsyncExitStack() as exit_stack:
        beta_setup_params.ip_stack = exit_ip_stack
        env = await setup_mesh_nodes(
            exit_stack, [alpha_setup_params, beta_setup_params]
        )

        _, beta = env.nodes
        client_alpha, client_beta = env.clients
        connection_alpha, connection_beta = [
            conn.connection for conn in env.connections
        ]

        if exit_ip_stack is not IPStack.IPv6:
            await ping(
                connection_alpha,
                testing.unpack_optional(beta.get_ip_address(IPProto.IPv4)),
            )
        else:
            await ping(
                connection_alpha,
                testing.unpack_optional(beta.get_ip_address(IPProto.IPv6)),
            )
        await client_beta.get_router().create_exit_node_route()

        await client_alpha.connect_to_exit_node(beta.public_key)

        ip_alpha = await stun.get(connection_alpha, config.STUN_SERVER)
        ip_beta = await stun.get(connection_beta, config.STUN_SERVER)

        assert ip_alpha == ip_beta

        # Testing if the exit node is cleared after disabling meshnet. See LLT-4266 for more details.
        # Since there's no way to get the actual events in the current NAT Lab API, using asyncio.wait() to await for a disconnect event future
        # and also all other events future, then checking which occurred first.
        disconnect_task = asyncio.create_task(
            client_alpha.wait_for_event_peer(
                beta.public_key,
                [NodeState.DISCONNECTED],
                list(PathType),
                is_exit=True,
            )
        )
        # Using a list of all NodeState variants except for Disconnect just in case new variants are added in the future.
        all_other_states = list(NodeState)
        all_other_states.remove(NodeState.DISCONNECTED)
        any_other_state_task = asyncio.create_task(
            client_alpha.wait_for_event_peer(
                beta.public_key, all_other_states, list(PathType)
            )
        )
        await client_alpha.set_mesh_off()
        done, pending = await asyncio.wait(
            [disconnect_task, any_other_state_task],
            timeout=5,
            return_when=asyncio.FIRST_COMPLETED,
        )
        assert (
            any_other_state_task in pending
        ), "Other events besides disconnect from beta happened after disabling meshnet"
        assert (
            disconnect_task in done
        ), "disconnect from beta never happened after disabling meshnet"
        with pytest.raises(asyncio.TimeoutError):
            await client_alpha.wait_for_event_peer(
                beta.public_key, list(NodeState), list(PathType), timeout=5
            )


@pytest.mark.parametrize(
    "exit_ip_stack",
    [
        pytest.param(
            IPStack.IPv6,
            marks=pytest.mark.ipv6,
        ),
        pytest.param(
            IPStack.IPv4v6,
            marks=pytest.mark.ipv4v6,
        ),
    ],
)
@pytest.mark.parametrize(
    "alpha_connection_tag,adapter_type",
    [
        pytest.param(ConnectionTag.DOCKER_CONE_CLIENT_1, TelioAdapterType.BORING_TUN),
        pytest.param(
            ConnectionTag.DOCKER_CONE_CLIENT_1,
            TelioAdapterType.LINUX_NATIVE_TUN,
            marks=pytest.mark.linux_native,
        ),
        pytest.param(
            ConnectionTag.WINDOWS_VM_1,
            TelioAdapterType.WINDOWS_NATIVE_TUN,
            marks=[
                pytest.mark.windows,
            ],
        ),
        pytest.param(
            ConnectionTag.WINDOWS_VM_1,
            TelioAdapterType.WIREGUARD_GO_TUN,
            marks=[
                pytest.mark.windows,
            ],
        ),
        pytest.param(
            ConnectionTag.MAC_VM, TelioAdapterType.BORING_TUN, marks=pytest.mark.mac
        ),
    ],
)
@pytest.mark.asyncio
async def test_ipv6_exit_node(
    alpha_connection_tag: ConnectionTag,
    adapter_type: TelioAdapterType,
    exit_ip_stack: IPStack,
) -> None:
    async with AsyncExitStack() as exit_stack:
        api = API()

        (alpha, beta) = api.default_config_two_nodes(
            alpha_ip_stack=IPStack.IPv4v6, beta_ip_stack=exit_ip_stack
        )
        (connection_alpha, alpha_conn_tracker) = await exit_stack.enter_async_context(
            new_connection_with_conn_tracker(
                alpha_connection_tag,
                generate_connection_tracker_config(
                    alpha_connection_tag,
                    derp_1_limits=ConnectionLimits(1, 1),
                    ping6_limits=ConnectionLimits(None, None),
                ),
            )
        )
        (connection_beta, beta_conn_tracker) = await exit_stack.enter_async_context(
            new_connection_with_conn_tracker(
                ConnectionTag.DOCKER_OPEN_INTERNET_CLIENT_DUAL_STACK,
                generate_connection_tracker_config(
                    ConnectionTag.DOCKER_OPEN_INTERNET_CLIENT_DUAL_STACK,
                    derp_1_limits=ConnectionLimits(1, 1),
                    # Dual stack doesn't have a gw so conntrack is launched on its interface
                    stun6_limits=ConnectionLimits(1, 1),
                    ping6_limits=ConnectionLimits(None, None),
                ),
            )
        )

        client_alpha = await exit_stack.enter_async_context(
            Client(connection_alpha, alpha, adapter_type).run(
                api.get_meshnet_config(alpha.id)
            )
        )

        client_beta = await exit_stack.enter_async_context(
            Client(connection_beta, beta).run(api.get_meshnet_config(beta.id))
        )

        await asyncio.gather(
            client_alpha.wait_for_state_on_any_derp([RelayState.CONNECTED]),
            client_beta.wait_for_state_on_any_derp([RelayState.CONNECTED]),
        )
        await asyncio.gather(
            client_alpha.wait_for_state_peer(beta.public_key, [NodeState.CONNECTED]),
            client_beta.wait_for_state_peer(alpha.public_key, [NodeState.CONNECTED]),
        )

        # Ping in-tunnel node with IPv6
        await ping(
            connection_alpha,
            testing.unpack_optional(beta.get_ip_address(IPProto.IPv6)),
        )
        await client_beta.get_router().create_exit_node_route()
        await client_alpha.connect_to_exit_node(beta.public_key)

        # Ping out-tunnel target with IPv6
        await ping(connection_alpha, config.PHOTO_ALBUM_IPV6)

        ip_alpha = await stun.get(connection_alpha, config.STUNV6_SERVER)
        ip_beta = await stun.get(connection_beta, config.STUNV6_SERVER)
        assert ip_alpha == ip_beta

        assert await alpha_conn_tracker.get_out_of_limits() is None
        assert await beta_conn_tracker.get_out_of_limits() is None
