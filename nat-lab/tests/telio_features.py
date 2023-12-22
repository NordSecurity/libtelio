from dataclasses import dataclass, field
from dataclasses_json import config, dataclass_json, Undefined, DataClassJsonMixin
from typing import Optional, List


def ExcludeIfNone(value) -> bool:
    return value is None


@dataclass_json
@dataclass
class ExitDns(DataClassJsonMixin):
    auto_switch_dns_ips: bool


@dataclass_json
@dataclass
class SkipUnresponsivePeers(DataClassJsonMixin):
    no_handshake_threshold_secs: int = 180


@dataclass_json
@dataclass
class Direct(DataClassJsonMixin):
    providers: Optional[List[str]] = None
    endpoint_interval_secs: Optional[int] = 5
    skip_unresponsive_peers: Optional[SkipUnresponsivePeers] = field(
        default_factory=lambda: SkipUnresponsivePeers(no_handshake_threshold_secs=180)
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


@dataclass_json
@dataclass
class NoLinkDetection(DataClassJsonMixin):
    rtt_seconds: Optional[int] = None


@dataclass_json
@dataclass
class PersistentKeepalive:
    vpn: Optional[int] = None
    direct: int = 5
    proxying: Optional[int] = None
    stun: Optional[int] = None


@dataclass_json
@dataclass
class Wireguard:
    persistent_keepalive: PersistentKeepalive


@dataclass_json(undefined=Undefined.EXCLUDE)
@dataclass
class TelioFeatures(DataClassJsonMixin):
    is_test_env: Optional[bool] = True
    exit_dns: Optional[ExitDns] = field(
        default_factory=lambda: ExitDns(auto_switch_dns_ips=True)
    )
    direct: Optional[Direct] = None
    lana: Optional[Lana] = None
    nurse: Optional[Nurse] = None
    ipv6: bool = False
    nicknames: bool = False
    boringtun_reset_connections: bool = False
    no_link_detection: Optional[NoLinkDetection] = None
    wireguard: Optional[Wireguard] = field(
        default=None, metadata=config(exclude=ExcludeIfNone)
    )
