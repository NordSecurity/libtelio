import pytest
from contextlib import AsyncExitStack
from tests.helpers import setup_mesh_nodes, SetupParameters
from tests.utils.bindings import default_features, TelioAdapterType
from tests.utils.connection import ConnectionTag, Connection, TargetOS
from tests.utils.multicast import MulticastClient, MulticastServer
from tests.utils.process import ProcessExecError
from typing import List, Tuple


def generate_setup_parameter_pair(
    cfg: List[Tuple[ConnectionTag, TelioAdapterType]],
) -> List[SetupParameters]:
    return [
        SetupParameters(
            connection_tag=conn_tag,
            adapter_type_override=adapter_type,
            features=default_features(enable_multicast=True),
        )
        for conn_tag, adapter_type in cfg
    ]


MUILTICAST_TEST_PARAMS = [
    pytest.param(
        generate_setup_parameter_pair([
            (ConnectionTag.DOCKER_FULLCONE_CLIENT_1, TelioAdapterType.NEP_TUN),
            (ConnectionTag.DOCKER_FULLCONE_CLIENT_2, TelioAdapterType.NEP_TUN),
        ]),
        "ssdp",
    ),
    pytest.param(
        generate_setup_parameter_pair([
            (ConnectionTag.DOCKER_SYMMETRIC_CLIENT_1, TelioAdapterType.NEP_TUN),
            (ConnectionTag.DOCKER_SYMMETRIC_CLIENT_2, TelioAdapterType.NEP_TUN),
        ]),
        "mdns",
    ),
    pytest.param(
        generate_setup_parameter_pair([
            (ConnectionTag.VM_WINDOWS_1, TelioAdapterType.WINDOWS_NATIVE_TUN),
            (ConnectionTag.DOCKER_CONE_CLIENT_1, TelioAdapterType.NEP_TUN),
        ]),
        "ssdp",
        marks=pytest.mark.windows,
    ),
    pytest.param(
        generate_setup_parameter_pair([
            (ConnectionTag.DOCKER_CONE_CLIENT_1, TelioAdapterType.NEP_TUN),
            (ConnectionTag.VM_WINDOWS_1, TelioAdapterType.WINDOWS_NATIVE_TUN),
        ]),
        "mdns",
        marks=pytest.mark.windows,
    ),
    pytest.param(
        generate_setup_parameter_pair([
            (ConnectionTag.VM_MAC, TelioAdapterType.NEP_TUN),
            (ConnectionTag.DOCKER_CONE_CLIENT_1, TelioAdapterType.NEP_TUN),
        ]),
        "ssdp",
        marks=pytest.mark.mac,
    ),
    pytest.param(
        generate_setup_parameter_pair([
            (ConnectionTag.DOCKER_CONE_CLIENT_1, TelioAdapterType.NEP_TUN),
            (ConnectionTag.VM_MAC, TelioAdapterType.NEP_TUN),
        ]),
        "mdns",
        marks=pytest.mark.mac,
    ),
]


async def add_multicast_route(connection: Connection) -> None:
    if connection.target_os == TargetOS.Linux:
        ipconf = connection.create_process(
            ["ip", "route", "add", "224.0.0.0/4", "dev", "tun10"]
        )
        await ipconf.execute()
    elif connection.target_os == TargetOS.Mac:
        ipconf = await connection.create_process(
            ["route", "delete", "224.0.0.0/4"]
        ).execute()
        ipconf = await connection.create_process(
            ["route", "add", "-net", "224.0.0.0/4", "-interface", "utun10"]
        ).execute()


@pytest.mark.asyncio
@pytest.mark.parametrize("setup_params, protocol", MUILTICAST_TEST_PARAMS)
async def test_multicast(setup_params: List[SetupParameters], protocol: str) -> None:
    async with AsyncExitStack() as exit_stack:
        env = await setup_mesh_nodes(exit_stack, setup_params)

        alpha_connection, beta_connection = [
            conn.connection for conn in env.connections
        ]

        await add_multicast_route(alpha_connection)
        await add_multicast_route(beta_connection)

        async with MulticastServer(beta_connection, protocol).run() as server:
            await server.wait_till_ready()
            await MulticastClient(alpha_connection, protocol).execute()


MUILTICAST_DISALLOWED_TEST_PARAMS = [
    pytest.param(
        generate_setup_parameter_pair([
            (ConnectionTag.DOCKER_FULLCONE_CLIENT_1, TelioAdapterType.NEP_TUN),
            (ConnectionTag.DOCKER_FULLCONE_CLIENT_2, TelioAdapterType.NEP_TUN),
        ]),
        "ssdp",
    ),
    pytest.param(
        generate_setup_parameter_pair([
            (ConnectionTag.DOCKER_SYMMETRIC_CLIENT_1, TelioAdapterType.NEP_TUN),
            (ConnectionTag.DOCKER_SYMMETRIC_CLIENT_2, TelioAdapterType.NEP_TUN),
        ]),
        "mdns",
    ),
]


@pytest.mark.asyncio
@pytest.mark.parametrize("setup_params, protocol", MUILTICAST_DISALLOWED_TEST_PARAMS)
async def test_multicast_disallowed(
    setup_params: List[SetupParameters], protocol: str
) -> None:
    async with AsyncExitStack() as exit_stack:
        env = await setup_mesh_nodes(exit_stack, setup_params)

        alpha_connection, beta_connection = [
            conn.connection for conn in env.connections
        ]

        client_alpha, client_beta = env.clients

        alpha, beta = env.nodes
        mesh_config_alpha = env.api.get_meshnet_config(alpha.id)
        if mesh_config_alpha.peers is not None:
            for peer in mesh_config_alpha.peers:
                if peer.base.hostname == beta.hostname:
                    peer.allow_multicast = False
        await client_alpha.set_meshnet_config(mesh_config_alpha)

        mesh_config_beta = env.api.get_meshnet_config(beta.id)
        if mesh_config_beta.peers is not None:
            for peer in mesh_config_beta.peers:
                if peer.base.hostname == alpha.hostname:
                    peer.peer_allows_multicast = False
        await client_beta.set_meshnet_config(mesh_config_beta)

        await add_multicast_route(alpha_connection)
        await add_multicast_route(beta_connection)

        async with MulticastServer(beta_connection, protocol).run() as server:
            with pytest.raises(ProcessExecError):
                await server.wait_till_ready()
                await MulticastClient(alpha_connection, protocol).execute()
