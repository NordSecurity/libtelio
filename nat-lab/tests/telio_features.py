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
class Direct(DataClassJsonMixin):
    providers: Optional[List[str]] = None
    endpoint_interval_secs: Optional[int] = 5
    skip_unresponsive_peers: Optional[SkipUnresponsivePeers] = field(
        default_factory=lambda: SkipUnresponsivePeers(no_rx_threshold_secs=180)
    )


@dataclass_json
@dataclass
class Lana(DataClassJsonMixin):
    prod: bool
    event_path: str


@dataclass_json(undefined=Undefined.EXCLUDE)
@dataclass
class Qos(DataClassJsonMixin):
    rtt_interval: Optional[int] = None
    rtt_tries: Optional[int] = None
    rtt_types: Optional[List[str]] = None
    buckets: Optional[int] = None


@dataclass_json(undefined=Undefined.EXCLUDE)
@dataclass
class Nurse(DataClassJsonMixin):
    fingerprint: str
    heartbeat_interval: Optional[int] = None
    initial_heartbeat_interval: Optional[int] = None
    qos: Optional[Qos] = None
    enable_nat_type_collection: bool = False


@dataclass_json(undefined=Undefined.EXCLUDE)
@dataclass
class LinkDetection(DataClassJsonMixin):
    rtt_seconds: Optional[int] = None


@dataclass_json(undefined=Undefined.EXCLUDE)
@dataclass
class Wireguard(DataClassJsonMixin):
    proxying: Optional[int] = 25
    direct: Optional[int] = 5
    vpn: Optional[int] = 25
    stun: Optional[int] = 25


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
