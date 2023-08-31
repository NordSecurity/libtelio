from contextlib import AsyncExitStack
from mesh_api import API
from utils import ConnectionTag, new_connection_by_tag
from telio import Client
from telio_features import TelioFeatures, Direct, Lana, Nurse, Qos, ExitDns
import asyncio
import pytest


@pytest.mark.asyncio
async def test_telio_tasks_with_all_features() -> None:
    async with AsyncExitStack() as exit_stack:
        api = API()
        alpha = api.default_config_alpha_node()
        connection_alpha = await exit_stack.enter_async_context(
            new_connection_by_tag(ConnectionTag.DOCKER_CONE_CLIENT_1)
        )
        client_alpha = await exit_stack.enter_async_context(
            Client(
                connection_alpha,
                alpha,
                telio_features=TelioFeatures(
                    macos_sideload=True,
                    exit_dns=ExitDns(auto_switch_dns_ips=True),
                    direct=Direct(providers=["stun", "local"]),
                    lana=Lana(prod=False, event_path="/some_path"),
                    nurse=Nurse(
                        fingerprint="alpha",
                        heartbeat_interval=3600,
                        initial_heartbeat_interval=10,
                        qos=Qos(
                            rtt_interval=5,
                            rtt_tries=3,
                            rtt_types=["Ping"],
                            buckets=5,
                        ),
                    ),
                ),
            ).run_meshnet(
                api.get_meshmap(alpha.id),
            )
        )
        # le wait some seconds for everything to start
        await asyncio.sleep(5)
        await client_alpha.stop_device()
