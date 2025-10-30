import pytest
from contextlib import AsyncExitStack
from helpers import SetupParameters, ping_between_all_nodes, setup_mesh_nodes
from typing import List
from utils.bindings import default_features, TelioAdapterType
from utils.connection import ConnectionTag


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
        tun = await alpha_client.create_tun(11)
        await alpha_client.start_with_tun(tun, "tun11")
        await alpha_client.set_meshnet_config(env.api.get_meshnet_config(alpha.id))
        await ping_between_all_nodes(env)


@pytest.mark.parametrize(
    "alpha_tag",
    [
        pytest.param(ConnectionTag.VM_MAC, marks=pytest.mark.mac),
        pytest.param(ConnectionTag.DOCKER_CONE_CLIENT_1),
    ],
)
async def test_start_with_tun_and_switch_it_at_runtime(alpha_tag) -> None:
    setup_params = _generate_setup_parameters([
        alpha_tag,
        ConnectionTag.DOCKER_CONE_CLIENT_2,
    ])

    tun_name_prefix = "utun" if alpha_tag == ConnectionTag.VM_MAC else "tun"

    async with AsyncExitStack() as exit_stack:

        env = await setup_mesh_nodes(exit_stack, setup_params)
        alpha_client, _ = env.clients
        alpha, _ = env.nodes

        await alpha_client.stop_device()

        tun11 = await alpha_client.create_tun(11)
        await alpha_client.start_with_tun(tun11, tun_name_prefix + "11")
        alpha_client.get_router().set_interface_name(tun_name_prefix + "11")
        await alpha_client.set_meshnet_config(env.api.get_meshnet_config(alpha.id))
        await alpha_client.get_router().delete_interface(tun_name_prefix + "10")
        await ping_between_all_nodes(env)

        tun12 = await alpha_client.create_tun(12)
        await alpha_client.get_proxy().set_tun(tun12)
        await alpha_client.restart_interface(new_name=tun_name_prefix + "12")
        await alpha_client.get_router().delete_interface(tun_name_prefix + "11")
        await ping_between_all_nodes(env)
