import asyncio
import pytest
from contextlib import AsyncExitStack
from helpers import setup_mesh_nodes, SetupParameters
from utils.bindings import (
    FeatureQoS,
    FeatureExitDns,
    FeatureDns,
    FeatureSkipUnresponsivePeers,
    EndpointProvider,
    RttType,
    FeaturesDefaultsBuilder,
)
from utils.connection_util import ConnectionTag


@pytest.mark.asyncio
async def test_telio_tasks_with_all_features() -> None:
    async with AsyncExitStack() as exit_stack:
        features = (
            FeaturesDefaultsBuilder()
            .enable_direct()
            .enable_lana("/some_path", False)
            .enable_nurse()
            .build()
        )
        assert features.direct
        features.direct.providers = [EndpointProvider.STUN, EndpointProvider.LOCAL]
        features.direct.skip_unresponsive_peers = FeatureSkipUnresponsivePeers(
            no_rx_threshold_secs=150
        )
        assert features.nurse
        features.nurse.initial_heartbeat_interval = 10
        features.nurse.qos = FeatureQoS(
            rtt_interval=5,
            rtt_tries=3,
            rtt_types=[RttType.PING],
            buckets=5,
        )
        features.nurse.enable_nat_type_collection = True
        features.dns = FeatureDns(
            exit_dns=FeatureExitDns(auto_switch_dns_ips=True),
            ttl_value=60,
        )
        env = await setup_mesh_nodes(
            exit_stack,
            [
                SetupParameters(
                    connection_tag=ConnectionTag.DOCKER_CONE_CLIENT_1,
                    features=features,
                    fingerprint="alpha",
                )
            ],
        )
        # let's wait some seconds for everything to start
        await asyncio.sleep(5)
        await env.clients[0].stop_device()
