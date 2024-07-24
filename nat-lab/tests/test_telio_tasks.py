import asyncio
import pytest
from contextlib import AsyncExitStack
from helpers import setup_mesh_nodes, SetupParameters
from telio_features import (
    TelioFeatures,
    Direct,
    Lana,
    Nurse,
    Qos,
    ExitDns,
    Dns,
    SkipUnresponsivePeers,
)
from utils.connection_util import ConnectionTag


@pytest.mark.asyncio
async def test_telio_tasks_with_all_features() -> None:
    async with AsyncExitStack() as exit_stack:
        env = await setup_mesh_nodes(
            exit_stack,
            [
                SetupParameters(
                    connection_tag=ConnectionTag.DOCKER_CONE_CLIENT_1,
                    features=TelioFeatures(
                        direct=Direct(
                            providers=["stun", "local"],
                            skip_unresponsive_peers=SkipUnresponsivePeers(
                                no_rx_threshold_secs=150
                            ),
                        ),
                        lana=Lana(prod=False, event_path="/some_path"),
                        nurse=Nurse(
                            heartbeat_interval=3600,
                            initial_heartbeat_interval=10,
                            qos=Qos(
                                rtt_interval=5,
                                rtt_tries=3,
                                rtt_types=["Ping"],
                                buckets=5,
                            ),
                            enable_relay_conn_data=True,
                            enable_nat_type_collection=True,
                        ),
                        dns=Dns(
                            exit_dns=ExitDns(auto_switch_dns_ips=True),
                            ttl_value=60,
                        ),
                    ),
                    fingerprint="alpha",
                )
            ],
        )
        # let's wait some seconds for everything to start
        await asyncio.sleep(5)
        await env.clients[0].stop_device()
