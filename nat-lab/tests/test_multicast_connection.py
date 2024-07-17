import pytest
from contextlib import AsyncExitStack
from helpers import setup_mesh_nodes, SetupParameters
from telio import AdapterType
from telio_features import TelioFeatures
from typing import List, Tuple
from utils.connection_util import ConnectionTag, Connection, TargetOS
from utils.multicast import MulticastClient, MulticastServer


def generate_setup_parameter_pair(
    cfg: List[Tuple[ConnectionTag, AdapterType]],
) -> List[SetupParameters]:
    return [
        SetupParameters(
            connection_tag=conn_tag,
            adapter_type=adapter_type,
            features=TelioFeatures(
                multicast=True,
            ),
        )
        for conn_tag, adapter_type in cfg
    ]


MUILTICAST_TEST_PARAMS = [
    pytest.param(
        generate_setup_parameter_pair([
            (ConnectionTag.DOCKER_FULLCONE_CLIENT_1, AdapterType.BoringTun),
            (ConnectionTag.DOCKER_FULLCONE_CLIENT_2, AdapterType.BoringTun),
        ]),
        "ssdp",
    ),
    pytest.param(
        generate_setup_parameter_pair([
            (ConnectionTag.DOCKER_SYMMETRIC_CLIENT_1, AdapterType.BoringTun),
            (ConnectionTag.DOCKER_SYMMETRIC_CLIENT_2, AdapterType.BoringTun),
        ]),
        "mdns",
    ),
    pytest.param(
        generate_setup_parameter_pair([
            (ConnectionTag.WINDOWS_VM_1, AdapterType.WireguardGo),
            (ConnectionTag.DOCKER_CONE_CLIENT_1, AdapterType.BoringTun),
        ]),
        "ssdp",
    ),
    pytest.param(
        generate_setup_parameter_pair([
            (ConnectionTag.DOCKER_CONE_CLIENT_1, AdapterType.BoringTun),
            (ConnectionTag.WINDOWS_VM_1, AdapterType.WindowsNativeWg),
        ]),
        "mdns",
    ),
]


async def add_multicast_route(connection: Connection) -> None:
    if connection.target_os == TargetOS.Linux:
        ipconf = connection.create_process(
            ["ip", "route", "add", "224.0.0.0/4", "dev", "tun10"]
        )
        await ipconf.execute()


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
