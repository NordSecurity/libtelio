from typing import Optional, Tuple

from uniffi.telio_bindings import *  # pylint: disable=wildcard-import, unused-wildcard-import  # isort: skip


def features_with_endpoint_providers(
    providers: Optional[list[EndpointProvider]],
) -> Features:
    features = default_features(enable_direct=True)
    assert features.direct
    features.direct.providers = providers
    return features


def default_features(
    enable_lana: Optional[Tuple[str, bool]] = None,
    enable_nurse: bool = False,
    enable_firewall_connection_reset: bool = False,
    enable_direct: bool = False,
    enable_ipv6: bool = False,
    enable_nicknames: bool = False,
    enable_link_detection: bool = False,
    enable_pmtu_discovery: bool = False,
    enable_multicast: bool = False,
) -> Features:
    features_builder = FeaturesDefaultsBuilder()
    if enable_lana is not None:
        event_path, prod = enable_lana
        features_builder = features_builder.enable_lana(event_path, prod)

    if enable_nurse:
        features_builder = features_builder.enable_nurse()
    if enable_firewall_connection_reset:
        features_builder = features_builder.enable_firewall_connection_reset()
    if enable_direct:
        features_builder = features_builder.enable_direct()
    if enable_ipv6:
        features_builder = features_builder.enable_ipv6()
    if enable_nicknames:
        features_builder = features_builder.enable_nicknames()
    if enable_link_detection:
        features_builder = features_builder.enable_link_detection()
    if enable_pmtu_discovery:
        features_builder = features_builder.enable_pmtu_discovery()
    if enable_multicast:
        features_builder = features_builder.enable_multicast()

    features = features_builder.build()
    features.is_test_env = True
    features.hide_ips = False
    features.dns.exit_dns = FeatureExitDns(auto_switch_dns_ips=True)
    return features
