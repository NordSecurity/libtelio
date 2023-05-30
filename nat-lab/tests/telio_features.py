from dataclasses import dataclass, field
from dataclasses_json import dataclass_json, Undefined
from typing import Optional, List


@dataclass_json
@dataclass
class ExitDns:
    auto_switch_dns_ips: bool


@dataclass_json
@dataclass
class Direct:
    providers: Optional[List[str]]


@dataclass_json
@dataclass
class Lana:
    prod: bool
    event_path: str


@dataclass_json(undefined=Undefined.EXCLUDE)
@dataclass
class Qos:
    rtt_interval: Optional[int] = None
    rtt_tries: Optional[int] = None
    rtt_types: Optional[List[str]] = None
    buckets: Optional[int] = None


@dataclass_json(undefined=Undefined.EXCLUDE)
@dataclass
class Nurse:
    fingerprint: str
    heartbeat_interval: Optional[int] = None
    qos: Optional[Qos] = None


@dataclass_json(undefined=Undefined.EXCLUDE)
@dataclass
class TelioFeatures:
    macos_sideload: Optional[bool] = False
    exit_dns: Optional[ExitDns] = field(
        default_factory=lambda: ExitDns(auto_switch_dns_ips=True)
    )
    direct: Optional[Direct] = None
    lana: Optional[Lana] = None
    nurse: Optional[Nurse] = None
