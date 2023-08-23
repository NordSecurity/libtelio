import os
import pprint
import time
import uuid
from config import DERP_SERVERS, WG_SERVERS
from python_wireguard import Key  # type: ignore
from typing import Dict, Any, List, Tuple, Optional
from utils.router import IPProto, get_ip_address_type

GREEK_ALPHABET = [
    "alpha",
    "beta",
    "gamma",
    "delta",
    "epsilon",
    "zeta",
    "eta",
    "theta",
    "iota",
    "kappa",
    "lambda",
    "mu",
    "nu",
    "xi",
    "omicron",
    "pi",
    "rho",
    "sigma",
    "tau",
    "upsilon",
    "phi",
    "chi",
    "psi",
    "omega",
]


class NodeError(Exception):
    node_id: str

    def __init__(self, node_id) -> None:
        self.node_id = node_id


class DuplicateNodeError(NodeError):
    pass


class MissingNodeError(NodeError):
    pass


class AddressCollisionError(NodeError):
    pass


class FirewallRule:
    allow_incoming_connections: bool
    allow_peer_send_files: bool

    def __init__(
        self,
        allow_incoming_connections: bool = False,
        allow_peer_send_files: bool = False,
    ):
        self.allow_incoming_connections = allow_incoming_connections
        self.allow_peer_send_files = allow_peer_send_files


class Node:
    name: str
    id: str
    private_key: str
    public_key: str

    hostname: str
    ip_addresses: List[str]
    endpoints: List[str]
    is_local: bool
    allow_connections: bool
    path_type: str
    firewall_rules: Dict[str, FirewallRule]

    def __init__(self):
        self.name = ""
        self.id = ""
        self.private_key = ""
        self.public_key = ""
        self.hostname = ""
        self.ip_addresses = []
        self.endpoints = []
        self.is_local = False
        self.allow_connections = False
        self.path_type = ""
        self.firewall_rules = {}

    def to_client_config(self) -> Dict[str, str]:
        return {
            "name": self.name,
            "id": self.id,
            "sk": self.private_key,
            "pk": self.public_key,
        }

    def to_peer_config_for_node(self, node) -> Dict[str, Any]:
        firewall_config = node.get_firewall_config(self.id)

        return {
            "identifier": self.id,
            "public_key": self.public_key,
            "hostname": self.hostname,
            "ip_addresses": self.ip_addresses,
            "endpoints": self.endpoints,
            "is_local": node.is_local and self.is_local,
            "allow_connections": self.allow_connections,
            "allow_incoming_connections": firewall_config.allow_incoming_connections,
            "allow_peer_send_files": firewall_config.allow_peer_send_files,
        }

    def set_peer_firewall_settings(
        self,
        node_id: str,
        allow_incoming_connections: bool = False,
        allow_peer_send_files: bool = False,
    ) -> None:
        self.firewall_rules[node_id] = FirewallRule(
            allow_incoming_connections, allow_peer_send_files
        )

    def get_firewall_config(self, node_id: str) -> FirewallRule:
        if node_id not in self.firewall_rules:
            return FirewallRule(
                allow_incoming_connections=False, allow_peer_send_files=False
            )
        return self.firewall_rules[node_id]

    # Pretty and informational string for debug messages, e.g. assert false, f"{node}"
    def __str__(self):
        return pprint.pformat(vars(self))


class API:
    nodes: Dict[str, Node]

    def __init__(self) -> None:
        self.nodes = {}

    def register(
        self, name: str, node_id: str, private_key: str, public_key: str, is_local=False
    ) -> Node:
        if node_id in self.nodes:
            raise DuplicateNodeError(node_id)

        node = Node()
        node.name = name
        node.id = node_id
        node.private_key = private_key
        node.public_key = public_key
        node.is_local = is_local
        node.hostname = name + ".nord"

        self.nodes[node_id] = node
        return node

    def remove(self, node_id) -> None:
        del self.nodes[node_id]

    def assign_ip(self, node_id: str, address: str) -> None:
        for _, node in self.nodes.items():
            if address in node.ip_addresses:
                raise AddressCollisionError(node.id)

        node = self._get_node(node_id)
        node.ip_addresses.append(address)

    def get_meshmap(
        self, node_id: str, derp_servers: Optional[List[Dict[str, Any]]] = None
    ) -> Dict[str, Any]:
        node = self._get_node(node_id)

        peers: List[Dict[str, Any]] = []
        for key, other_node in self.nodes.items():
            if key != node_id:
                peers.append(other_node.to_peer_config_for_node(node))

        meshmap = {
            "identifier": node.id,
            "public_key": node.public_key,
            "hostname": node.hostname,
            "ip_addresses": node.ip_addresses,
            "endpoints": node.endpoints,
            "peers": peers,
            "derp_servers": derp_servers if derp_servers is not None else DERP_SERVERS,
        }

        return meshmap

    def default_config_one_node(self, is_local: bool = False) -> Node:
        alpha, *_ = self.config_dynamic_nodes([is_local])
        return alpha

    def default_config_two_nodes(
        self, alpha_is_local: bool = False, beta_is_local: bool = False
    ) -> Tuple[Node, Node]:
        alpha, beta, *_ = self.config_dynamic_nodes([alpha_is_local, beta_is_local])
        alpha.set_peer_firewall_settings(beta.id, True)
        beta.set_peer_firewall_settings(alpha.id, True)
        return alpha, beta

    def default_config_three_nodes(
        self,
        alpha_is_local: bool = False,
        beta_is_local: bool = False,
        gamma_is_local: bool = False,
    ) -> Tuple[Node, Node, Node]:
        alpha, beta, gamma, *_ = self.config_dynamic_nodes(
            [alpha_is_local, beta_is_local, gamma_is_local]
        )
        alpha.set_peer_firewall_settings(gamma.id, allow_incoming_connections=True)
        alpha.set_peer_firewall_settings(beta.id, allow_incoming_connections=True)
        beta.set_peer_firewall_settings(alpha.id, allow_incoming_connections=True)
        beta.set_peer_firewall_settings(gamma.id, allow_incoming_connections=True)
        gamma.set_peer_firewall_settings(alpha.id, allow_incoming_connections=True)
        gamma.set_peer_firewall_settings(beta.id, allow_incoming_connections=True)
        return alpha, beta, gamma

    def _get_node(self, node_id: str) -> Node:
        if node_id not in self.nodes:
            raise MissingNodeError(node_id)
        return self.nodes[node_id]

    @classmethod
    def get_allowed_ip_list(cls, addrs: List[str]) -> List[str]:
        return [
            ip + ("/32" if ip_type == IPProto.IPv4 else "/128")
            for ip in addrs
            if (ip_type := get_ip_address_type(ip)) is not None
        ]

    @classmethod
    def setup_wg_servers(cls, node_list: List[Node], server_config: Dict[str, Any]):
        def generate_peer_config(node: Node, allowed_ips: str) -> str:
            return (
                f"[Peer]\nPublicKey = {node.public_key}\nAllowedIPs = {allowed_ips}\n\n"
            )

        wg_conf = (
            f"[Interface]\nPrivateKey = {server_config['private_key']}\nListenPort ="
            f" {server_config['port']}\nAddress = 100.64.0.1/10, fd00::1/64\n\n"
        )

        for node in node_list:
            wg_conf += generate_peer_config(
                node, ", ".join(cls.get_allowed_ip_list(node.ip_addresses))
            )

        full_command = (
            f"docker exec -d --privileged {server_config['container']} bash -c 'echo"
            f' "{wg_conf}" > /etc/wireguard/wg0.conf; wg-quick down'
            " /etc/wireguard/wg0.conf; wg-quick up /etc/wireguard/wg0.conf'"
        )
        os.system(full_command)

    def config_dynamic_nodes(self, node_configs: List[bool]) -> Tuple[Node, ...]:
        current_node_list_len = len(self.nodes)
        for idx, is_local in enumerate(node_configs):
            node_idx = current_node_list_len + idx
            private, public = Key.key_pair()
            node = self.register(
                name=GREEK_ALPHABET[node_idx],
                node_id=str(uuid.uuid1(node=node_idx, clock_seq=int(time.time()))),
                private_key=str(private),
                public_key=str(public),
                is_local=is_local,
            )
            # TODO correct subnet when we'll decide about the range
            self.assign_ip(node.id, f"100.64.33.{node_idx}")
            self.assign_ip(node.id, f"fd00::dead:{node_idx}")

        for wg_server in WG_SERVERS:
            self.setup_wg_servers(list(self.nodes.values()), wg_server)

        assert (len(node_configs) + current_node_list_len) == len(self.nodes)

        return tuple(list(self.nodes.values())[current_node_list_len:])
