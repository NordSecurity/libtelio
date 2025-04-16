import asyncio
import pytest
from contextlib import AsyncExitStack
from helpers import SetupParameters, ping_between_all_nodes, setup_mesh_nodes
from typing import List
from utils.bindings import default_features, TelioAdapterType
from utils.connection import ConnectionTag
from utils.logger import log


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

@pytest.mark.timeout(40)
async def test_start_with_tun_and_switch() -> None:
    setup_params = _generate_setup_parameters([
        ConnectionTag.DOCKER_CONE_CLIENT_1,
        ConnectionTag.DOCKER_CONE_CLIENT_2,
    ])

    async with AsyncExitStack() as exit_stack:
        
        env = await setup_mesh_nodes(exit_stack, setup_params)
        alpha_client, _ = env.clients
        alpha_connection, _ = env.connections
        alpha, _ = env.nodes

        await ping_between_all_nodes(env)
        await alpha_client.stop_device()
        tun11 = await alpha_client.create_tun("tun11")
        log.info("tun11 created, will delete tun10")

        

        await alpha_client.start_with_tun(tun11, "tun11")
        log.info("started with tun11")
        await alpha_client.set_meshnet_config(env.api.get_meshnet_config(alpha.id))
        log.info("set mesh config tun11 done, will delete tun10")
        # await alpha_connection.connection.create_process(
        #     ["ip", "link", "delete", "tun10"]).execute(privileged=True)
        log.info("Will ping:")
        await ping_between_all_nodes(env)
        log.info("Will create new tun12")

        tun12 = await alpha_client.create_tun("tun12")
        log.info("Tun12 is %s", tun12)
        await alpha_client.get_proxy().set_tun(tun12)
        
        await alpha_client.restart_interface(new_name="tun12")
        # alpha_client.get_router().set_interface_name("tun12")
        # await alpha_client._configure_interface()

        # await alpha_client.set_meshnet_config(env.api.get_meshnet_config(alpha.id))
        # await alpha_connection.connection.create_process(
        #     ["ip", "link", "delete", "tun11"]).execute()
        
        log.info("will ping in 1s")
        await asyncio.sleep(1)
        await ping_between_all_nodes(env)
        log.info("test can now end")
