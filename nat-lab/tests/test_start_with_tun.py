from contextlib import AsyncExitStack
from helpers import SetupParameters, ping_between_all_nodes, setup_mesh_nodes
from typing import List
from utils.bindings import default_features, TelioAdapterType
from utils.connection_util import ConnectionTag


def _generate_setup_parameters(
    conn_tags: List[ConnectionTag],
) -> List[SetupParameters]:
    return [
        SetupParameters(
            connection_tag=conn_tag,
            adapter_type_override=TelioAdapterType.BORING_TUN,
            features=default_features(),
            fingerprint=f"{conn_tag}",
        )
        for conn_tag in conn_tags
    ]


async def test_start_with_tun() -> None:
    setup_params = _generate_setup_parameters([
        ConnectionTag.DOCKER_CONE_CLIENT_1,
        ConnectionTag.DOCKER_CONE_CLIENT_2,
    ])

    async with AsyncExitStack() as exit_stack:
        env = await setup_mesh_nodes(exit_stack, setup_params)
        alpha_client, _ = env.clients
        alpha, _ = env.nodes

        await ping_between_all_nodes(env)
        await alpha_client.stop_device()
        tun = await alpha_client.create_tun("tun11")
        await alpha_client.start_with_tun(tun, "tun11")
        await alpha_client.set_meshnet_config(env.api.get_meshnet_config(alpha.id))
        await ping_between_all_nodes(env)
