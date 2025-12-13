from typing import Optional, Tuple, List

from tests.uniffi.telio_bindings import *  # pylint: disable=wildcard-import, unused-wildcard-import  # isort: skip


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
    enable_firewall_exclusion_range: Optional[str] = None,
    enable_direct: bool = False,
    enable_ipv6: bool = False,
    enable_nicknames: bool = False,
    enable_link_detection: bool = False,
    enable_multicast: bool = False,
    enable_dynamic_wg_nt_control: bool = False,
    custom_skt_buffer_size: Optional[int] = None,
    custom_inter_thread_channel_size: Optional[int] = None,
    custom_max_inter_thread_batched_pkts: Optional[int] = None,
    enable_error_notification_service: bool = False,
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
    if enable_multicast:
        features_builder = features_builder.enable_multicast()
    if enable_dynamic_wg_nt_control:
        features_builder = features_builder.enable_dynamic_wg_nt_control()
    if custom_skt_buffer_size:
        features_builder = features_builder.set_skt_buffer_size(custom_skt_buffer_size)
    if custom_inter_thread_channel_size:
        features_builder = features_builder.set_inter_thread_channel_size(
            custom_inter_thread_channel_size
        )
    if custom_max_inter_thread_batched_pkts:
        features_builder = features_builder.set_max_inter_thread_batched_pkts(
            custom_max_inter_thread_batched_pkts
        )
    if enable_error_notification_service:
        features_builder = features_builder.enable_error_notification_service()

    features = features_builder.build()
    features.is_test_env = True
    features.hide_user_data = False
    features.hide_thread_id = False
    features.dns.exit_dns = FeatureExitDns(auto_switch_dns_ips=True)
    if enable_firewall_exclusion_range is not None:
        if features.firewall is None:
            features.firewall = FeatureFirewall(
                neptun_reset_conns=False,
                boringtun_reset_conns=False,
                exclude_private_ip_range=None,
                outgoing_blacklist=[],
            )
        features.firewall.exclude_private_ip_range = enable_firewall_exclusion_range
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
    allow_peer_traffic_routing: bool = False,
    allow_peer_local_network_access: bool = False,
    link_state: Optional[LinkState] = None,
    allow_multicast: bool = True,
    peer_allows_multicast: bool = True,
    vpn_connection_error=None,
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
        allow_peer_traffic_routing=allow_peer_traffic_routing,
        allow_peer_local_network_access=allow_peer_local_network_access,
        link_state=link_state,
        allow_multicast=allow_multicast,
        peer_allows_multicast=peer_allows_multicast,
        vpn_connection_error=vpn_connection_error,
    )
