import asyncio
import pytest
from contextlib import AsyncExitStack
from helpers import setup_mesh_nodes, SetupParameters
from utils.bindings.features import (
    features,
    feature_direct,
    FeatureLana,
    feature_nurse,
    FeatureQoS,
    FeatureExitDns,
    FeatureDns,
    FeatureSkipUnresponsivePeers,
    EndpointProvider,
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
                    features=features(
                        direct=feature_direct(
                            providers=[EndpointProvider.STUN, EndpointProvider.LOCAL],
                            skip_unresponsive_peers=FeatureSkipUnresponsivePeers(
                                no_rx_threshold_secs=150
                            ),
                        ),
                        lana=FeatureLana(prod=False, event_path="/some_path"),
                        nurse=feature_nurse(
                            initial_heartbeat_interval=10,
                            qos=FeatureQoS(
                                rtt_interval=5,
                                rtt_tries=3,
                                rtt_types=["Ping"],
                                buckets=5,
                            ),
                            enable_nat_type_collection=True,
                        ),
                        dns=FeatureDns(
                            exit_dns=FeatureExitDns(auto_switch_dns_ips=True),
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
