from typing import Dict, Any, List, Tuple
from config import *
import pprint


class NodeError(Exception):
    node_id: str

    def __init__(self, id) -> None:
        self.node_id = id


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
        id: str,
        allow_incoming_connections: bool = False,
        allow_peer_send_files: bool = False,
    ) -> None:
        self.firewall_rules[id] = FirewallRule(
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
        self, name: str, id: str, private_key: str, public_key: str, is_local=False
    ) -> Node:
        if id in self.nodes:
            raise DuplicateNodeError(id)

        node = Node()
        node.name = name
        node.id = id
        node.private_key = private_key
        node.public_key = public_key
        node.is_local = is_local
        node.hostname = name + ".nord"

        self.nodes[id] = node
        return node

    def remove(self, id) -> None:
        del self.nodes[id]

    def assign_ip(self, id: str, address: str) -> None:
        for _, node in self.nodes.items():
            if address in node.ip_addresses:
                raise AddressCollisionError(node.id)

        node = self._get_node(id)
        node.ip_addresses.append(address)

    def get_meshmap(
        self,
        id: str,
        derp_servers: List[Dict[str, Any]] = DERP_SERVERS,
    ) -> Dict[str, Any]:
        node = self._get_node(id)

        peers: List[Dict[str, Any]] = []
        for key, other_node in self.nodes.items():
            if key != id:
                peers.append(other_node.to_peer_config_for_node(node))

        meshmap = {
            "identifier": node.id,
            "public_key": node.public_key,
            "hostname": node.hostname,
            "ip_addresses": node.ip_addresses,
            "endpoints": node.endpoints,
            "peers": peers,
            "derp_servers": derp_servers,
        }

        return meshmap

    def default_config_three_nodes(
        self,
        alpha_is_local: bool = False,
        beta_is_local: bool = False,
        gamma_is_local: bool = False,
    ) -> Tuple[Node, Node, Node]:
        alpha = self.register(
            name="alpha",
            id="96ddb926-4b86-11ec-81d3-0242ac130003",
            private_key="IGm+42FLMMGZRaQvk6F3UPbl+T/CBk8W+NPoX2/AdlU=",
            public_key="41CCEssnYIh8/8D8YvbTfWEcFanG3D0I0z1tRcN1Lyc=",
            is_local=alpha_is_local,
        )

        beta = self.register(
            name="beta",
            id="7b4548ca-fe5a-4597-8513-896f38c6d6ae",
            private_key="SPFD84gPtBNc3iGY9Cdrj+mSCwBeh3mCMWfPaeWQolw=",
            public_key="Q1M3VKUcfTmGsrRzY6BpNds1yDIUvPVcs/2TySv/t1U=",
            is_local=beta_is_local,
        )

        gamma = self.register(
            name="gamma",
            id="39388b1e-ebd8-11ec-8ea0-0242ac120002",
            private_key="+ARXeBavEK8jESD8UIo1z/0LRUla++UXdqN65UQ2Mk8=",
            public_key="q2V4fN+JLtparAblRdb6QylWpYm3kU86H4fLQTNkJzM=",
            is_local=gamma_is_local,
        )

        self.assign_ip(alpha.id, ALPHA_NODE_ADDRESS)
        self.assign_ip(beta.id, BETA_NODE_ADDRESS)
        self.assign_ip(gamma.id, GAMMA_NODE_ADDRESS)

        alpha.set_peer_firewall_settings(beta.id, allow_incoming_connections=True)
        beta.set_peer_firewall_settings(alpha.id, allow_incoming_connections=True)
        alpha.set_peer_firewall_settings(gamma.id, allow_incoming_connections=True)
        gamma.set_peer_firewall_settings(alpha.id, allow_incoming_connections=True)
        beta.set_peer_firewall_settings(gamma.id, allow_incoming_connections=True)
        gamma.set_peer_firewall_settings(beta.id, allow_incoming_connections=True)

        return (alpha, beta, gamma)

    def _get_node(self, id: str) -> Node:
        if id not in self.nodes:
            raise MissingNodeError(id)
        return self.nodes[id]
