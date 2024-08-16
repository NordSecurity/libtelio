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


def telio_node(  # pylint: disable=dangerous-default-value
    identifier: str = "",
    public_key: str = "",
    state: NodeState = NodeState.DISCONNECTED,
    link_state: Optional[LinkState] = None,
    is_exit: bool = False,
    is_vpn: bool = False,
    ip_addresses: list[str] = [],
    allowed_ips: list[str] = [],
    nickname: Optional[str] = None,
    endpoint: Optional[str] = None,
    hostname: Optional[str] = None,
    allow_incoming_connections: bool = False,
    allow_peer_send_files: bool = False,
    path: PathType = PathType.RELAY,
    allow_multicast: bool = False,
    peer_allows_multicast: bool = False,
) -> TelioNode:
    return TelioNode(
        identifier=identifier,
        public_key=public_key,
        state=state,
        link_state=link_state,
        is_exit=is_exit,
        is_vpn=is_vpn,
        ip_addresses=ip_addresses,
        allowed_ips=allowed_ips,
        nickname=nickname,
        endpoint=endpoint,
        hostname=hostname,
        allow_incoming_connections=allow_incoming_connections,
        allow_peer_send_files=allow_peer_send_files,
        path=path,
        allow_multicast=allow_multicast,
        peer_allows_multicast=peer_allows_multicast,
    )
