from contextlib import AsyncExitStack
from mesh_api import API
from utils import ConnectionTag, new_connection_by_tag
import telio
from telio_features import TelioFeatures, Direct, Lana, Nurse, Qos, ExitDns
import asyncio
import pytest


@pytest.mark.asyncio
async def test_telio_tasks_with_all_features() -> None:
    async with AsyncExitStack() as exit_stack:
        api = API()

        alpha = api.register(
            name="alpha",
            id="96ddb926-4b86-11ec-81d3-0242ac130003",
            private_key="JcnzdKlaRd56T/EnHkbVpNCvYo64YLDpRZsJq14ZU1A=",
            public_key="eES5D8OiQyMXf/pG0ibJSD2QhSnKLW0+6jW7mvtfL0g=",
        )

        api.assign_ip(alpha.id, "100.64.0.11")

        client_alpha = await exit_stack.enter_async_context(
            telio.run_meshnet(
                await exit_stack.enter_async_context(
                    new_connection_by_tag(ConnectionTag.DOCKER_CONE_CLIENT_1)
                ),
                alpha,
                api.get_meshmap(alpha.id),
                telio_features=TelioFeatures(
                    macos_sideload=True,
                    exit_dns=ExitDns(auto_switch_dns_ips=True),
                    direct=Direct(providers=["stun", "local"]),
                    lana=Lana(prod=False, event_path="/some_path"),
                    nurse=Nurse(
                        fingerprint="alpha",
                        qos=Qos(
                            rtt_interval=5,
                            rtt_tries=3,
                            rtt_types=["Ping"],
                            buckets=5,
                            heartbeat_interval=3600,
                        ),
                    ),
                ),
            )
        )
        # le wait some seconds for everything to start
        await asyncio.sleep(5)
        await client_alpha.stop_device()
