import pytest
from dataclasses import dataclass
from tests import config
from tests.helpers import Environment, SetupParameters
from tests.helpers_vpn import connect_vpn
from tests.libtelio_client import Client
from tests.mesh_api import Node
from tests.uniffi.libtelio_proxy import LibtelioError
from tests.utils.bindings import TelioAdapterType
from tests.utils.connection import ConnectionTag
from tests.utils.ping import ping
from typing import Awaitable, Callable, List

ALPHA_SETUP_PARAMS = [
    pytest.param(
        SetupParameters(
            connection_tag=ConnectionTag.DOCKER_CONE_CLIENT_1,
            adapter_type_override=TelioAdapterType.NEP_TUN,
        ),
        id="neptun",
    ),
    pytest.param(
        SetupParameters(
            connection_tag=ConnectionTag.DOCKER_CONE_CLIENT_1,
            adapter_type_override=TelioAdapterType.LINUX_NATIVE_TUN,
        ),
        marks=pytest.mark.linux_native,
        id="linux_native",
    ),
    pytest.param(
        SetupParameters(
            connection_tag=ConnectionTag.VM_WINDOWS_1,
            adapter_type_override=TelioAdapterType.WINDOWS_NATIVE_TUN,
        ),
        marks=pytest.mark.windows,
        id="windows_native",
    ),
    pytest.param(
        SetupParameters(
            connection_tag=ConnectionTag.VM_MAC,
            adapter_type_override=TelioAdapterType.NEP_TUN,
        ),
        marks=pytest.mark.mac,
        id="mac",
    ),
]

BETA_SETUP_PARAMS = [
    pytest.param(
        SetupParameters(connection_tag=ConnectionTag.DOCKER_CONE_CLIENT_2),
        id="beta",
    )
]

VPN_PUBLIC_KEY = str(config.WG_SERVER["public_key"])
VPN_ENDPOINT = f'{config.WG_SERVER["ipv4"]}:{config.WG_SERVER["port"]}'


@dataclass(frozen=True)
class FailingConnect:
    connect: Callable[[Client, Node], Awaitable[None]]
    error: str


async def connect_post_quantum_with_meshnet_on(client: Client, _peer: Node) -> None:
    await client.get_proxy().connect_to_exit_node_pq(
        public_key=VPN_PUBLIC_KEY, allowed_ips=None, endpoint=VPN_ENDPOINT
    )


async def connect_without_endpoint(client: Client, _peer: Node) -> None:
    await client.get_proxy().connect_to_exit_node(
        public_key=VPN_PUBLIC_KEY, allowed_ips=None, endpoint=None
    )


FAILING_CONNECTS = [
    pytest.param(
        FailingConnect(
            connect_post_quantum_with_meshnet_on, "MeshnetUnavailableWithPQ"
        ),
        id="post_quantum_with_meshnet_on",
    ),
    pytest.param(
        FailingConnect(connect_without_endpoint, "EndpointNotProvided"),
        id="no_endpoint",
    ),
]


# Module-level override, env_mesh gets VPN_1
@pytest.fixture(name="vpn_tags")
def _vpn_tags() -> List[ConnectionTag]:
    return [ConnectionTag.DOCKER_VPN_1]


@pytest.mark.asyncio
@pytest.mark.parametrize("failing_connect", FAILING_CONNECTS)
@pytest.mark.parametrize("alpha_setup_params", ALPHA_SETUP_PARAMS)
@pytest.mark.parametrize("beta_setup_params", BETA_SETUP_PARAMS)
async def test_failed_exit_node_connect_keeps_libtelio_running(
    alpha_setup_params: SetupParameters,  # pylint: disable=unused-argument
    beta_setup_params: SetupParameters,  # pylint: disable=unused-argument
    env_mesh: Environment,
    failing_connect: FailingConnect,
) -> None:
    """LLT-7765: a failed exit node connect returns its own error and stops nothing."""
    alpha, beta = env_mesh.nodes
    client_alpha, *_ = env_mesh.clients
    connection_alpha = env_mesh.connections[0].connection

    await ping(connection_alpha, beta.ip_addresses[0])

    with pytest.raises(LibtelioError, match=failing_connect.error):
        await failing_connect.connect(client_alpha, beta)

    assert await client_alpha.get_proxy().is_running()
    await ping(connection_alpha, beta.ip_addresses[0])

    await client_alpha.get_proxy().disconnect_from_exit_nodes()
    await client_alpha.set_meshnet_config(env_mesh.api.get_meshnet_config(alpha.id))
    await connect_vpn(
        connection_alpha, None, client_alpha, alpha.ip_addresses[0], config.WG_SERVER
    )

    await ping(connection_alpha, beta.ip_addresses[0])
