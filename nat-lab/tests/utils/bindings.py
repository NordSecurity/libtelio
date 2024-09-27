from typing import Optional, Tuple, List

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
    enable_firewall: Optional[Tuple[str, bool]] = None,
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
    if enable_firewall is not None:
        ips, reset_conns = enable_firewall
        features_builder = features_builder.enable_firewall(ips, reset_conns)
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


def telio_node(  # pylint: disable=dangerous-default-value
    identifier: str = "",
    public_key: str = "",
    state: NodeState = NodeState.DISCONNECTED,
    hostname: Optional[str] = None,
    nickname: Optional[str] = None,
    is_exit: bool = False,
    is_vpn: bool = False,
    ip_addresses: List[str] = [],
    allowed_ips: List[str] = [],
    endpoint: Optional[str] = None,
    path: PathType = PathType.RELAY,
    allow_incoming_connections: bool = False,
    allow_peer_send_files: bool = False,
    link_state: Optional[LinkState] = None,
    allow_multicast: bool = False,
    peer_allows_multicast: bool = False,
) -> TelioNode:
    return TelioNode(
        identifier=identifier,
        public_key=public_key,
        state=state,
        hostname=hostname,
        nickname=nickname,
        is_exit=is_exit,
        is_vpn=is_vpn,
        ip_addresses=ip_addresses,
        allowed_ips=allowed_ips,
        endpoint=endpoint,
        path=path,
        allow_incoming_connections=allow_incoming_connections,
        allow_peer_send_files=allow_peer_send_files,
        link_state=link_state,
        allow_multicast=allow_multicast,
        peer_allows_multicast=peer_allows_multicast,
    )
