import os
import platform
import pprint
import random
import time
import uuid
from config import DERP_SERVERS, LIBTELIO_IPV6_WG_SUBNET, WG_SERVERS
from ipaddress import ip_address
from typing import Dict, Any, List, Tuple, Optional
from utils.router import IPStack, IPProto, get_ip_address_type
from utils.testing import test_name_safe_for_file_name

if platform.machine() != "x86_64":
    import pure_wg as Key
else:
    from python_wireguard import Key  # type: ignore

Meshmap = Dict[str, Any]

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

PCAP_FILE_PATH = "/dump.pcap"


class NodeError(Exception):
    node_id: str

    def __init__(self, node_id) -> None:
        self.node_id = node_id


class NicknameError(Exception):
    nickname: str

    def __init__(self, nickname) -> None:
        self.nickname = nickname


class DuplicateNodeError(NodeError):
    pass


class MissingNodeError(NodeError):
    pass


class AddressCollisionError(NodeError):
    pass


class NicknameInvalidError(NicknameError):
    pass


class NicknameCollisionError(NodeError):
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
    nickname: Optional[str]
    endpoints: List[str]
    is_local: bool
    allow_connections: bool
    path_type: str
    firewall_rules: Dict[str, FirewallRule]
    ip_stack: IPStack

    def __init__(self):
        self.name = ""
        self.id = ""
        self.private_key = ""
        self.public_key = ""
        self.hostname = ""
        self.ip_addresses = []
        self.nickname = None
        self.endpoints = []
        self.is_local = False
        self.allow_connections = False
        self.path_type = ""
        self.firewall_rules = {}
        self.ip_stack = IPStack.IPv4

    def to_client_config(self) -> Dict[str, str]:
        return {
            "name": self.name,
            "id": self.id,
            "sk": self.private_key,
            "pk": self.public_key,
        }

    def get_ip_address(self, ip_proto: IPProto) -> Optional[str]:
        if not self.ip_addresses:
            return None

        if self.ip_stack in [IPStack.IPv4, IPStack.IPv6]:
            # Only one address in our basket
            if get_ip_address_type(self.ip_addresses[0]) == ip_proto:
                return format(ip_address(self.ip_addresses[0]))
        else:
            # Dual stack, so two addresses (or more)
            for addr in self.ip_addresses:
                if get_ip_address_type(addr) == ip_proto:
                    return format(ip_address(addr))

        return None

    def to_peer_config_for_node(self, node) -> Dict[str, Any]:
        firewall_config = node.get_firewall_config(self.id)

        return {
            "identifier": self.id,
            "public_key": self.public_key,
            "hostname": self.hostname,
            "ip_addresses": self.ip_addresses,
            "nickname": self.nickname,
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
        self,
        name: str,
        node_id: str,
        private_key: str,
        public_key: str,
        is_local=False,
        ip_stack: IPStack = IPStack.IPv4,
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
        node.ip_stack = ip_stack

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

    def assign_nickname(self, node_id: str, nickname: Optional[str]) -> None:
        if nickname is None:
            raise NicknameInvalidError(nickname)
        if len(nickname) > 25:
            raise NicknameInvalidError(nickname)
        if nickname == "":
            raise NicknameInvalidError(nickname)
        if " " in nickname:
            raise NicknameInvalidError(nickname)
        if "--" in nickname:
            raise NicknameInvalidError(nickname)
        if nickname.endswith("-"):
            raise NicknameInvalidError(nickname)
        if nickname.startswith("-"):
            raise NicknameInvalidError(nickname)

        for _, node in self.nodes.items():
            if nickname == node.nickname:
                raise NicknameCollisionError(node.id)
            if nickname == node.name:
                raise NicknameCollisionError(node.id)
            if nickname == node.hostname:
                raise NicknameCollisionError(node.id)

        node = self._get_node(node_id)
        node.nickname = nickname.lower()

    def reset_nickname(self, node_id: str) -> None:
        node = self._get_node(node_id)
        node.nickname = None

    def get_meshmap(
        self, node_id: str, derp_servers: Optional[List[Dict[str, Any]]] = None
    ) -> Meshmap:
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
            "nickname": node.nickname,
            "endpoints": node.endpoints,
            "peers": peers,
            "derp_servers": derp_servers if derp_servers is not None else DERP_SERVERS,
        }

        return meshmap

    def default_config_one_node(
        self,
        is_local: bool = False,
        ip_stack: IPStack = IPStack.IPv4,
    ) -> Node:
        alpha, *_ = self.config_dynamic_nodes([(is_local, ip_stack)])
        return alpha

    def default_config_two_nodes(
        self,
        alpha_is_local: bool = False,
        beta_is_local: bool = False,
        alpha_ip_stack: IPStack = IPStack.IPv4,
        beta_ip_stack: IPStack = IPStack.IPv4,
    ) -> Tuple[Node, Node]:
        alpha, beta, *_ = self.config_dynamic_nodes(
            [(alpha_is_local, alpha_ip_stack), (beta_is_local, beta_ip_stack)]
        )
        alpha.set_peer_firewall_settings(beta.id, True)
        beta.set_peer_firewall_settings(alpha.id, True)
        return alpha, beta

    def default_config_three_nodes(
        self,
        alpha_is_local: bool = False,
        beta_is_local: bool = False,
        gamma_is_local: bool = False,
        alpha_ip_stack: IPStack = IPStack.IPv4,
        beta_ip_stack: IPStack = IPStack.IPv4,
        gamma_ip_stack: IPStack = IPStack.IPv4,
    ) -> Tuple[Node, Node, Node]:
        alpha, beta, gamma, *_ = self.config_dynamic_nodes([
            (alpha_is_local, alpha_ip_stack),
            (beta_is_local, beta_ip_stack),
            (gamma_is_local, gamma_ip_stack),
        ])
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
    def setup_vpn_servers(cls, node_list: List[Node], server_config: Dict[str, Any]):
        def generate_peer_config(node: Node, allowed_ips: str) -> str:
            return (
                f"[Peer]\nPublicKey = {node.public_key}\nAllowedIPs = {allowed_ips}\n\n"
            )

        wg_conf = (
            f"[Interface]\nPrivateKey = {server_config['private_key']}\nListenPort ="
            f" {server_config['port']}\nAddress = 100.64.0.1/10\n\n"
        )

        for node in node_list:
            _start_tcpdump_on_vpn(server_config["container"])
            if "type" in server_config and server_config["type"] == "nordlynx":
                priv_key = server_config["private_key"]
                commands = [
                    f"echo {priv_key} > /etc/nordlynx/private.key",
                    "nlx set nordlynx0 private-key /etc/nordlynx/private.key",
                ]

                for cmd in commands:
                    os.system(
                        f"docker exec -d --privileged {server_config['container']} bash -c '{cmd}'"
                    )

            else:
                wg_conf += generate_peer_config(
                    node, ", ".join(cls.get_allowed_ip_list(node.ip_addresses))
                )
                cmd = (
                    f"docker exec -d --privileged {server_config['container']} bash -c"
                    f' \'echo "{wg_conf}" > /etc/wireguard/wg0.conf; wg-quick down'
                    " /etc/wireguard/wg0.conf; wg-quick up /etc/wireguard/wg0.conf'"
                )
                os.system(cmd)

    def config_dynamic_nodes(
        self, node_configs: List[Tuple[bool, IPStack]]
    ) -> Tuple[Node, ...]:
        current_node_list_len = len(self.nodes)
        for idx, (is_local, ip_stack) in enumerate(node_configs):
            node_idx = current_node_list_len + idx
            private, public = Key.key_pair()
            node = self.register(
                name=GREEK_ALPHABET[node_idx],
                node_id=str(uuid.uuid1(node=node_idx, clock_seq=int(time.time()))),
                private_key=str(private),
                public_key=str(public),
                is_local=is_local,
                ip_stack=ip_stack,
            )
            ipv4 = f"100.{random.randint(64, 127)}.{random.randint(0, 255)}.{random.randint(8, 254)}"
            ipv6 = f"{LIBTELIO_IPV6_WG_SUBNET}:0:{format(random.randint(0, 0xFFFF), 'x')}:{format(random.randint(0, 0xFFFF), 'x')}:{format(random.randint(0, 0xFFFF), 'x')}:{format(random.randint(8, 0xFFFF), 'x')}"

            if ip_stack in [IPStack.IPv4, IPStack.IPv4v6]:
                self.assign_ip(node.id, ipv4)

            if ip_stack in [IPStack.IPv6, IPStack.IPv4v6]:
                self.assign_ip(node.id, ipv6)

        for wg_server in WG_SERVERS:
            self.setup_vpn_servers(list(self.nodes.values()), wg_server)

        assert (len(node_configs) + current_node_list_len) == len(self.nodes)

        return tuple(list(self.nodes.values())[current_node_list_len:])


def _start_tcpdump_on_vpn(server_name):
    if os.environ.get("NATLAB_SAVE_LOGS") is None:
        return
    # First make sure that no leftover processes/files will interfere
    cmd = f"docker exec --privileged {server_name} killall tcpdump"
    os.system(cmd)
    cmd = f"docker exec --privileged {server_name} rm {PCAP_FILE_PATH}"
    os.system(cmd)

    cmd = f"docker exec -d --privileged {server_name} tcpdump -i any -U -w {PCAP_FILE_PATH}"
    os.system(cmd)


def stop_tcpdump_on_vpns():
    if os.environ.get("NATLAB_SAVE_LOGS") is None:
        return
    test_name = test_name_safe_for_file_name()
    log_dir = "logs"
    os.makedirs(log_dir, exist_ok=True)
    for wg_server in WG_SERVERS:
        server_name = wg_server["container"]
        cmd = f"docker exec --privileged {server_name} killall tcpdump"
        os.system(cmd)
        cmd = f"docker container cp {server_name}:{PCAP_FILE_PATH} ./{log_dir}/{test_name}-{server_name}.pcap"
        os.system(cmd)
