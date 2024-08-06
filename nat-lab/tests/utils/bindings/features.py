from typing import Optional, List
from uniffi.telio_bindings import (
    Features,
    FeatureWireguard,
    FeatureNurse,
    FeatureLana,
    FeaturePaths,
    FeatureDirect,
    FeatureDerp,
    FeatureFirewall,
    FeatureLinkDetection,
    FeatureDns,
    FeaturePostQuantumVpn,
    FeaturePmtuDiscovery,
    FeaturePersistentKeepalive,
    FeatureQoS,
    FeatureEndpointProvidersOptimization,
    FeatureSkipUnresponsivePeers,
    EndpointProvider,
    RttType,
)

from uniffi.telio_bindings import (  # isort:skip  # noqa  # pylint: disable=unused-import
    FeatureExitDns,
)


def feature_direct(
    providers: Optional[List[EndpointProvider]] = [],
    endpoint_interval_secs: Optional[int] = 10,
    skip_unresponsive_peers: Optional[
        FeatureSkipUnresponsivePeers
    ] = FeatureSkipUnresponsivePeers(180),
    endpoint_providers_optimization: Optional[
        FeatureEndpointProvidersOptimization
    ] = None,
) -> FeatureDirect:
    return FeatureDirect(
        providers,
        endpoint_interval_secs,
        skip_unresponsive_peers,
        endpoint_providers_optimization,
    )


def feature_persistent_keepalive(
    vpn: Optional[int] = 25,
    direct: int = 5,
    proxying: Optional[int] = 25,
    stun: Optional[int] = 25,
) -> FeaturePersistentKeepalive:
    return FeaturePersistentKeepalive(vpn, direct, proxying, stun)


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


def features(
    wireguard: FeatureWireguard = FeatureWireguard(
        persistent_keepalive=feature_persistent_keepalive()
    ),
    nurse: Optional[FeatureNurse] = None,
    lana: Optional[FeatureLana] = None,
    paths: Optional[FeaturePaths] = None,
    direct: Optional[FeatureDirect] = None,
    is_test_env: Optional[bool] = None,
    derp: Optional[FeatureDerp] = None,
    validate_keys: bool = True,
    ipv6: bool = False,
    nicknames: bool = False,
    firewall: FeatureFirewall = FeatureFirewall(boringtun_reset_conns=False),
    flush_events_on_stop_timeout_seconds: Optional[int] = 0,
    link_detection: Optional[FeatureLinkDetection] = None,
    dns: FeatureDns = FeatureDns(ttl_value=60, exit_dns=None),
    post_quantum_vpn: FeaturePostQuantumVpn = FeaturePostQuantumVpn(
        handshake_retry_interval_s=8, rekey_interval_s=90
    ),
    pmtu_discovery: Optional[FeaturePmtuDiscovery] = FeaturePmtuDiscovery(
        response_wait_timeout_s=5
    ),
    multicast: bool = False,
) -> Features:
    return Features(
        wireguard,
        nurse,
        lana,
        paths,
        direct,
        is_test_env,
        derp,
        validate_keys,
        ipv6,
        nicknames,
        firewall,
        flush_events_on_stop_timeout_seconds,
        link_detection,
        dns,
        post_quantum_vpn,
        pmtu_discovery,
        multicast,
    )
