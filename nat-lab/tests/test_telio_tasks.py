import asyncio
import pytest
from tests.helpers import SetupParameters, Environment
from tests.utils.bindings import (
    FeatureQoS,
    FeatureExitDns,
    FeatureDns,
    FeatureSkipUnresponsivePeers,
    EndpointProvider,
    RttType,
    default_features,
)
from tests.utils.connection import ConnectionTag

pytest_plugins = ["tests.helpers_fixtures"]

_FEATURES = default_features(
    enable_direct=True, enable_lana=("/some_path", False), enable_nurse=True
)
assert _FEATURES.direct
_FEATURES.direct.providers = [EndpointProvider.STUN, EndpointProvider.LOCAL]
_FEATURES.direct.skip_unresponsive_peers = FeatureSkipUnresponsivePeers(
    no_rx_threshold_secs=150
)
assert _FEATURES.nurse
_FEATURES.nurse.initial_heartbeat_interval = 10
_FEATURES.nurse.qos = FeatureQoS(
    rtt_interval=5,
    rtt_tries=3,
    rtt_types=[RttType.PING],
    buckets=5,
)
_FEATURES.dns = FeatureDns(
    exit_dns=FeatureExitDns(auto_switch_dns_ips=True),
    ttl_value=60,
)


@pytest.mark.parametrize(
    "alpha_setup_params",
    [
        pytest.param(
            SetupParameters(
                connection_tag=ConnectionTag.DOCKER_CONE_CLIENT_1,
                features=_FEATURES,
                fingerprint="alpha",
            ),
        ),
    ],
)
@pytest.mark.asyncio
async def test_telio_tasks_with_all_features(
    alpha_setup_params: SetupParameters,  # pylint: disable=unused-argument
    env_mesh: Environment,
) -> None:
    alpha_client = env_mesh.clients[0]

    # let's wait some seconds for everything to start
    await asyncio.sleep(5)
    await alpha_client.stop_device()
