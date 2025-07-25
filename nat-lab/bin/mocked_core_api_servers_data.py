from dataclasses import dataclass
from typing import List, Dict


@dataclass
class City:
    id: int
    name: str
    latitude: float
    longitude: float
    dns_name: str


@dataclass
class Country:
    id: int
    name: str
    code: str
    city: City


@dataclass
class Location:
    id: int
    created_at: str
    updated_at: str
    longitude: float
    latitude: float
    country: Country


@dataclass
class Service:
    id: int
    name: str
    identifier: str
    created_at: str
    updated_at: str


@dataclass
class TechnologyPivot:
    server_id: int
    technology_id: int
    status: str


@dataclass
class Metadata:
    name: str
    value: str


@dataclass
class Technology:
    id: int
    name: str
    identifier: str
    created_at: str
    updated_at: str
    metadata: List[Metadata]
    pivot: TechnologyPivot


@dataclass
class GroupType:
    id: int
    created_at: str
    updated_at: str
    title: str
    identifier: str


@dataclass
class Group:
    id: int
    created_at: str
    updated_at: str
    title: str
    type: GroupType


@dataclass
class SpecificationValue:
    id: int
    value: str


@dataclass
class Specification:
    id: int
    title: str
    identifier: str
    values: List[SpecificationValue]


@dataclass
class IPInfo:
    id: int
    ip: str
    version: int


@dataclass
class ServerIP:
    id: int
    created_at: str
    updated_at: str
    server_id: int
    ip_id: int
    type: str
    ip: IPInfo


@dataclass
class Server:
    id: int
    created_at: str
    updated_at: str
    name: str
    station: str
    hostname: str
    load: int
    status: str
    locations: List[Location]
    services: List[Service]
    technologies: List[Technology]
    groups: List[Group]
    specifications: List[Specification]
    ips: List[ServerIP]


country_poland = {
    "id": 1,
    "name": "Poland",
    "code": "PL"
}

country_germany = {
    "id": 2,
    "name": "Germany",
    "code": "DE"
}

server_poland = {
    "id": 1,
    "created_at": "2024-12-16 00:00:00",
    "updated_at": "2024-12-11 15:21:19",
    "name": "Poland #128",
    "station": "10.0.100.1",
    "hostname": "pl128.nordvpn.com",
    "load": 21,
    "status": "online",
    "locations": [
        {
            "id": 1,
            "created_at": "2024-06-15 14:06:47",
            "updated_at": "2024-06-15 14:06:47",
            "longitude": 21,
            "latitude": 52.25,
            "country": {
                "id": 1,
                "name": "Poland",
                "code": "PL",
                "city": {
                    "id": 6863429,
                    "name": "Warsaw",
                    "latitude": 52.25,
                    "longitude": 21,
                    "dns_name": "warsaw"
                }
            }
        }
    ],
    "services": [
        {
            "id": 1,
            "name": "VPN",
            "identifier": "vpn",
            "created_at": "2017-03-21 12:00:45",
            "updated_at": "2017-05-25 13:12:31"
        }
    ],
    "technologies": [
        {
            "id": 11,
            "name": "PPTP",
            "identifier": "pptp",
            "created_at": "2017-05-09 19:29:16",
            "updated_at": "2017-05-09 19:29:16",
            "pivot": {
                "server_id": 1,
                "technology_id": 11,
                "status": "online"
            }
        },
        {
            "id": 35,
            "name": "Wireguard",
            "identifier": "wireguard_udp",
            "created_at": "2019-02-14 14:08:43",
            "updated_at": "2019-02-14 14:08:43",
            "metadata": [
                {
                    "name": "public_key",
                    "value": "kjAOzXQRVGpmQdqE2zPsITH8QHmFK83AAPktqWed9wM="
                },
            ],
            "pivot": {
                "technology_id": 35,
                "server_id": 1,
                "status": "online"
            }
        },
    ],
    "groups": [],
    "specifications": [],
    "ips": [
        {
            "id": 1019456,
            "created_at": "2023-07-14 07:40:33",
            "updated_at": "2023-07-14 07:40:33",
            "server_id": 1,
            "ip_id": 23702,
            "type": "entry",
            "ip": {
                "id": 23702,
                "ip": "10.0.100.1",
                "version": 4
            }
        }
    ]
}

server_germany = {
    "id": 2,
    "created_at": "2023-12-16 00:00:00",
    "updated_at": "2023-12-11 15:21:19",
    "name": "Germany #1263",
    "station": "10.0.100.2",
    "hostname": "de1263.nordvpn.com",
    "load": 7,
    "status": "online",
    "locations": [
        {
            "id": 1,
            "created_at": "2023-06-15 14:06:47",
            "updated_at": "2023-06-15 14:06:47",
            "longitude": 13.4,
            "latitude": 52.516667,
            "country": {
                "id": 2,
                "name": "Germany",
                "code": "DE",
                "city": {
                    "id": 2181458,
                    "name": "Berlin",
                    "latitude": 52.516667,
                    "longitude": 13.4,
                    "dns_name": "berlin"
                }
            }
        }
    ],
    "services": [
        {
            "id": 1,
            "name": "VPN",
            "identifier": "vpn",
            "created_at": "2017-03-21 12:00:45",
            "updated_at": "2017-05-25 13:12:31"
        }
    ],
    "technologies": [
        {
            "id": 11,
            "name": "PPTP",
            "identifier": "pptp",
            "created_at": "2017-05-09 19:29:16",
            "updated_at": "2017-05-09 19:29:16",
            "pivot": {
                "server_id": 1,
                "technology_id": 11,
                "status": "online"
            }
        },
        {
            "id": 35,
            "name": "Wireguard",
            "identifier": "wireguard_udp",
            "created_at": "2019-02-14 14:08:43",
            "updated_at": "2019-02-14 14:08:43",
            "metadata": [
                {
                    "name": "public_key",
                    "value": "kjAOzXQRVGpmQdqE2zPsITH8QHmFK83AAPktqWed9wM="
                },
            ],
            "pivot": {
                "technology_id": 35,
                "server_id": 1,
                "status": "online"
            }
        },
    ],
    "groups": [],
    "specifications": [],
    "ips": [
        {
            "id": 1019456,
            "created_at": "2023-07-14 07:40:33",
            "updated_at": "2023-07-14 07:40:33",
            "server_id": 1,
            "ip_id": 23702,
            "type": "entry",
            "ip": {
                "id": 23702,
                "ip": "10.0.100.2",
                "version": 4
            }
        }
    ]
}

country_to_server_mapping = {
    1: server_poland,
    2: server_germany,
}


def get_countries() -> List[Dict]:
    countries = [country_poland, country_germany]
    return countries


def get_servers(filters: Dict[str, str]) -> List[Server]:
    country_id = int(filters.get("country_id", 1))
    city_id = int(filters.get("country_city_id", 1))
    print(f"Passed city and country filters: {city_id}, {country_id} ")
    vpn_server = country_to_server_mapping.get(country_id, None)
    if not vpn_server:
        return []

    return [Server(
        id=vpn_server["id"],
        created_at=vpn_server["created_at"],
        updated_at=vpn_server["updated_at"],
        name=vpn_server["name"],
        station=vpn_server["station"],
        hostname=vpn_server["hostname"],
        load=vpn_server["load"],
        status=vpn_server["status"],
        locations=[
            Location(
                id=loc["id"],
                created_at=loc["created_at"],
                updated_at=loc["updated_at"],
                longitude=loc["longitude"],
                latitude=loc["latitude"],
                country=Country(
                    id=loc["country"]["id"],
                    name=loc["country"]["name"],
                    code=loc["country"]["code"],
                    city=City(
                        id=loc["country"]["city"]["id"],
                        name=loc["country"]["city"]["name"],
                        latitude=loc["country"]["city"]["latitude"],
                        longitude=loc["country"]["city"]["longitude"],
                        dns_name=loc["country"]["city"]["dns_name"]
                    )
                )
            )
            for loc in vpn_server["locations"]
        ],
        services=[
            Service(**svc) for svc in vpn_server["services"]
        ],
        technologies=[
            Technology(
                id=tech["id"],
                name=tech["name"],
                identifier=tech["identifier"],
                created_at=tech["created_at"],
                updated_at=tech["updated_at"],
                metadata=tech.get("metadata", []),
                pivot=TechnologyPivot(**tech["pivot"])
            )
            for tech in vpn_server["technologies"]
        ],
        groups=[
            Group(
                id=grp["id"],
                created_at=grp["created_at"],
                updated_at=grp["updated_at"],
                title=grp["title"],
                type=GroupType(**grp["type"])
            )
            for grp in vpn_server.get("groups", [])
        ],
        specifications=[
            Specification(
                id=spec["id"],
                title=spec["title"],
                identifier=spec["identifier"],
                values=[
                    SpecificationValue(**val) for val in spec["values"]
                ]
            )
            for spec in vpn_server.get("specifications", [])
        ],
        ips=[
            ServerIP(
                id=ip["id"],
                created_at=ip["created_at"],
                updated_at=ip["updated_at"],
                server_id=ip["server_id"],
                ip_id=ip["ip_id"],
                type=ip["type"],
                ip=IPInfo(**ip["ip"])
            )
            for ip in vpn_server.get("ips", [])
        ]
    )]
