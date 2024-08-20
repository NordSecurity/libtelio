from typing import Optional
from uniffi.telio_bindings import *  # pylint: disable=wildcard-import, unused-wildcard-import


def feature_nurse(
    heartbeat_interval: int = 3600,
    initial_heartbeat_interval: int = 300,
    qos: Optional[FeatureQoS] = FeatureQoS(
        rtt_interval=300, rtt_tries=3, rtt_types=[RttType.PING], buckets=5
    ),
    enable_nat_type_collection: bool = False,
    enable_relay_conn_data: bool = True,
    enable_nat_traversal_conn_data: bool = True,
    state_duration_cap: int = 24 * 60 * 60,
) -> FeatureNurse:
    return FeatureNurse(
        heartbeat_interval,
        initial_heartbeat_interval,
        qos,
        enable_nat_type_collection,
        enable_relay_conn_data,
        enable_nat_traversal_conn_data,
        state_duration_cap,
    )


def features_with_endpoint_providers(
    providers: Optional[list[EndpointProvider]],
) -> Features:
    features = FeaturesDefaultsBuilder().enable_direct().build()
    assert features.direct
    features.direct.providers = providers
    return features
