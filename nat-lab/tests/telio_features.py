from dataclasses import dataclass, field
from dataclasses_json import dataclass_json, Undefined, DataClassJsonMixin
from typing import Optional, List


@dataclass_json
@dataclass
class ExitDns(DataClassJsonMixin):
    auto_switch_dns_ips: bool


@dataclass_json
@dataclass
class Dns(DataClassJsonMixin):
    exit_dns: Optional[ExitDns]
    ttl_value: int


@dataclass_json
@dataclass
class SkipUnresponsivePeers(DataClassJsonMixin):
    no_rx_threshold_secs: int = 180


@dataclass_json
@dataclass
class FeatureEndpointProvidersOptimization(DataClassJsonMixin):
    optimize_direct_upgrade_stun: bool = True
    optimize_direct_upgrade_upnp: bool = True


@dataclass_json
@dataclass
class Direct(DataClassJsonMixin):
    providers: Optional[List[str]] = None
    endpoint_interval_secs: Optional[int] = 5
    skip_unresponsive_peers: Optional[SkipUnresponsivePeers] = field(
        default_factory=lambda: SkipUnresponsivePeers(no_rx_threshold_secs=180)
    )
    endpoint_providers_optimization: Optional[FeatureEndpointProvidersOptimization] = (
        field(
            default_factory=lambda: FeatureEndpointProvidersOptimization(
                optimize_direct_upgrade_stun=True,
                optimize_direct_upgrade_upnp=True,
            )
        )
    )


@dataclass_json
@dataclass
class Lana(DataClassJsonMixin):
    prod: bool
    event_path: str


@dataclass_json(undefined=Undefined.EXCLUDE)
@dataclass
class Qos(DataClassJsonMixin):
    rtt_interval: int = 300
    rtt_tries: int = 3
    rtt_types: List[str] = field(default_factory=lambda: ["Ping"])
    buckets: int = 5


@dataclass_json(undefined=Undefined.EXCLUDE)
@dataclass
class Nurse(DataClassJsonMixin):
    fingerprint: str
    heartbeat_interval: int = 3600
    initial_heartbeat_interval: int = 300
    qos: Optional[Qos] = None
    enable_nat_type_collection: bool = False
    enable_relay_conn_data: bool = False
    enable_nat_traversal_conn_data: bool = False


@dataclass_json(undefined=Undefined.EXCLUDE)
@dataclass
class LinkDetection(DataClassJsonMixin):
    rtt_seconds: Optional[int] = None


@dataclass_json(undefined=Undefined.EXCLUDE)
@dataclass
class PersistentKeepalive(DataClassJsonMixin):
    proxying: Optional[int] = 25
    direct: Optional[int] = 5
    vpn: Optional[int] = 25
    stun: Optional[int] = 25


@dataclass_json(undefined=Undefined.EXCLUDE)
@dataclass
class Wireguard(DataClassJsonMixin):
    persistent_keepalive: PersistentKeepalive


@dataclass_json(undefined=Undefined.EXCLUDE)
@dataclass
class PmtuDiscovery(DataClassJsonMixin):
    response_wait_timeout_s: Optional[int] = 1


@dataclass_json(undefined=Undefined.EXCLUDE)
@dataclass
class PostQuantumVPN(DataClassJsonMixin):
    handshake_retry_interval_s: Optional[int]
    rekey_interval_s: Optional[int]


@dataclass_json(undefined=Undefined.EXCLUDE)
@dataclass
class TelioFeatures(DataClassJsonMixin):
    is_test_env: Optional[bool] = True
    direct: Optional[Direct] = None
    lana: Optional[Lana] = None
    nurse: Optional[Nurse] = None
    ipv6: bool = False
    nicknames: bool = False
    boringtun_reset_connections: bool = False
    link_detection: Optional[LinkDetection] = None
    wireguard: Optional[Wireguard] = None
    dns: Dns = field(
        default_factory=lambda: Dns(
            exit_dns=ExitDns(auto_switch_dns_ips=True),
            ttl_value=60,
        )
    )
    pmtu_discovery: Optional[PmtuDiscovery] = None
    post_quantum_vpn: PostQuantumVPN = field(
        default_factory=lambda: PostQuantumVPN(
            handshake_retry_interval_s=8, rekey_interval_s=90
        )
    )
    multicast: bool = False
