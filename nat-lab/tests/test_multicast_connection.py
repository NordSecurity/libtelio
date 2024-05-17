import pytest
import telio
from contextlib import AsyncExitStack
from helpers import setup_mesh_nodes, SetupParameters
from telio_features import TelioFeatures
from typing import List
from utils.connection_util import ConnectionTag
from utils.multicast import MulticastClient, MulticastServer


def generate_setup_parameter_pair(
    cfg: List[ConnectionTag],
) -> List[SetupParameters]:
    return [
        SetupParameters(
            connection_tag=conn_tag,
            adapter_type=telio.AdapterType.BoringTun,
            features=TelioFeatures(
                multicast=True,
            ),
        )
        for conn_tag in cfg
    ]


MUILTICAST_TEST_PARAMS = [
    pytest.param(
        generate_setup_parameter_pair([
            ConnectionTag.DOCKER_FULLCONE_CLIENT_1,
            ConnectionTag.DOCKER_FULLCONE_CLIENT_2,
        ]),
        "ssdp",
    ),
    pytest.param(
        generate_setup_parameter_pair([
            ConnectionTag.DOCKER_FULLCONE_CLIENT_1,
            ConnectionTag.DOCKER_FULLCONE_CLIENT_2,
        ]),
        "mdns",
    ),
]


@pytest.mark.asyncio
@pytest.mark.parametrize("setup_params, protocol", MUILTICAST_TEST_PARAMS)
async def test_multicast(setup_params: List[SetupParameters], protocol: str) -> None:
    async with AsyncExitStack() as exit_stack:
        env = await setup_mesh_nodes(exit_stack, setup_params)

        alpha_connection, beta_connection = [
            conn.connection for conn in env.connections
        ]

        ipconf = alpha_connection.create_process(
            ["ip", "route", "add", "224.0.0.0/4", "dev", "tun10"]
        )
        await ipconf.execute()
        ipconf = beta_connection.create_process(
            ["ip", "route", "add", "224.0.0.0/4", "dev", "tun10"]
        )
        await ipconf.execute()

        async with MulticastServer(beta_connection, protocol).run() as server:
            await server.wait_till_ready()
            await MulticastClient(alpha_connection, protocol).execute()
