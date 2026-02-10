import json
import platform
import pprint
import random
import subprocess
import time
import uuid
from ipaddress import ip_address
from tests.config import DERP_SERVERS, LIBTELIO_IPV6_WG_SUBNET, WG_SERVERS
from tests.utils.bindings import Config, Server, Peer, PeerBase
from tests.utils.connection import Connection, ConnectionTag
from tests.utils.logger import log
from tests.utils.router import IPStack, IPProto, get_ip_address_type
from typing import Dict, Any, List, Tuple, Optional

if platform.machine() != "x86_64":
    import tests.pure_wg as Key
else:
    from python_wireguard import Key  # type: ignore

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


class NicknameError(Exception):
    nickname: str

    def __init__(self, nickname) -> None:
        self.nickname = nickname


class DuplicateNodeError(NodeError):
    pass


class MissingNodeError(NodeError):
    pass


class NicknameInvalidError(NicknameError):
    pass


class NicknameCollisionError(NodeError):
    pass


class FirewallRule:
    allow_incoming_connections: bool
    allow_peer_traffic_routing: bool
    allow_peer_local_network_access: bool
    allow_peer_send_files: bool

    def __init__(
        self,
        allow_incoming_connections: bool = False,
        allow_peer_traffic_routing: bool = False,
        allow_peer_local_network_access: bool = False,
        allow_peer_send_files: bool = False,
    ):
        self.allow_incoming_connections = allow_incoming_connections
        self.allow_peer_send_files = allow_peer_send_files
        self.allow_peer_local_network_access = allow_peer_local_network_access
        self.allow_peer_traffic_routing = allow_peer_traffic_routing

    def __str__(self):
        return pprint.pformat(vars(self))


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

    def to_peer_config_for_node(self, node) -> Peer:
        firewall_config = node.get_firewall_config(self.id)

        return Peer(
            base=PeerBase(
                identifier=self.id,
                public_key=self.public_key,
                hostname=self.hostname,
                ip_addresses=self.ip_addresses,
                nickname=self.nickname,
            ),
            is_local=node.is_local and self.is_local,
            allow_incoming_connections=firewall_config.allow_incoming_connections,
            allow_peer_traffic_routing=firewall_config.allow_peer_traffic_routing,
            allow_peer_local_network_access=firewall_config.allow_peer_local_network_access,
            allow_peer_send_files=firewall_config.allow_peer_send_files,
            allow_multicast=True,
            peer_allows_multicast=True,
        )

    def set_peer_firewall_settings(
        self,
        node_id: str,
        allow_incoming_connections: bool = False,
        allow_peer_send_files: bool = False,
        allow_peer_traffic_routing: bool = False,
    ) -> None:
        self.firewall_rules[node_id] = FirewallRule(
            allow_incoming_connections,
            allow_peer_send_files=allow_peer_send_files,
            allow_peer_traffic_routing=allow_peer_traffic_routing,
        )

    def get_firewall_config(self, node_id: str) -> FirewallRule:
        if node_id not in self.firewall_rules:
            return FirewallRule(
                allow_incoming_connections=False, allow_peer_send_files=False
            )
        return self.firewall_rules[node_id]

    # Pretty and informational string for debug messages, e.g. assert false, f"{node}"
    def __str__(self):
        node_dict = vars(self).copy()
        node_dict["firewall_rules"] = {
            key: rule.to_dict() if hasattr(rule, "to_dict") else str(rule)
            for key, rule in self.firewall_rules.items()
        }
        node_dict["ip_stack"] = (
            self.ip_stack.to_dict()
            if hasattr(self.ip_stack, "to_dict")
            else str(self.ip_stack)
        )
        return json.dumps(node_dict, indent=4, sort_keys=True, ensure_ascii=False)


class API:
    nodes: Dict[str, Node]

    def __init__(self) -> None:
        self.nodes = {}

    def register(  # pylint: disable=dangerous-default-value
        self,
        name: str,
        node_id: str,
        private_key: str,
        public_key: str,
        is_local=False,
        ip_stack: IPStack = IPStack.IPv4,
        ip_addresses: Optional[List[str]] = None,
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
        if ip_addresses is not None:
            node.ip_addresses = ip_addresses

        self.nodes[node_id] = node
        return node

    def remove(self, node_id) -> None:
        del self.nodes[node_id]

    def assign_random_ip(self, node_id: str, proto: IPProto) -> None:
        def get_random_ip(proto: IPProto) -> str:
            if proto == IPProto.IPv4:
                return f"100.{random.randint(64, 127)}.{random.randint(0, 255)}.{random.randint(8, 254)}"
            return f"{LIBTELIO_IPV6_WG_SUBNET}:0:{format(random.randint(0, 0xFFFF), 'x')}:{format(random.randint(0, 0xFFFF), 'x')}:{format(random.randint(0, 0xFFFF), 'x')}:{format(random.randint(8, 0xFFFF), 'x')}"

        address = get_random_ip(proto)
        while any(address in node.ip_addresses for node in self.nodes.values()):
            address = get_random_ip(proto)

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

    def get_meshnet_config(
        self, node_id: str, derp_servers: Optional[List[Server]] = None
    ) -> Config:
        node = self._get_node(node_id)

        peers = [
            other_node.to_peer_config_for_node(node)
            for key, other_node in self.nodes.items()
            if key != node_id
        ]

        meshnet_config = Config(
            this=PeerBase(
                identifier=node.id,
                public_key=node.public_key,
                hostname=node.hostname,
                ip_addresses=node.ip_addresses,
                nickname=node.nickname,
            ),
            peers=peers,
            derp_servers=derp_servers if derp_servers is not None else DERP_SERVERS,
            dns=None,
        )

        return meshnet_config

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
        allow_peer_traffic_routing: bool = False,
    ) -> Tuple[Node, Node]:
        alpha, beta, *_ = self.config_dynamic_nodes(
            [(alpha_is_local, alpha_ip_stack), (beta_is_local, beta_ip_stack)]
        )
        alpha.set_peer_firewall_settings(beta.id, True)
        beta.set_peer_firewall_settings(
            alpha.id, True, allow_peer_traffic_routing=allow_peer_traffic_routing
        )
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
    async def setup_vpn_servers(
        cls,
        node_list: List[Node],
        server_config: Dict[str, Any],
        connections: Optional[List[Connection]] = None,
    ):
        def generate_peer_config(node: Node, allowed_ips: str) -> str:
            return (
                f"[Peer]\nPublicKey = {node.public_key}\nAllowedIPs = {allowed_ips}\n\n"
            )

        if server_config.get("type") == "nordlynx":
            if "public_key" in server_config and "private_key" in server_config:
                return

            if not connections:
                return

            container = server_config.get("container")

            for conn in connections:
                if conn.tag != ConnectionTag.VM_LINUX_NLX_1:
                    continue

                get_pub_cmd = (
                    'nlx | awk \'$1=="public" && $2=="key:" {print $3; exit}\''
                )
                proc = await conn.create_process(["bash", "-lc", get_pub_cmd]).execute()
                pub_key = proc.get_stdout().strip()

                if not pub_key:
                    raise RuntimeError(
                        f"Could not obtain NordLynx public key from nlx on {container}"
                    )
                server_config["public_key"] = pub_key
                log.debug(
                    "NordLynx public key for %s: %s",
                    server_config.get("container"),
                    pub_key,
                )

                get_priv_cmd = (
                    "nlx showconf nordlynx0 | "
                    'awk \'$1=="PrivateKey" && $2=="=" {print $3; exit}\''
                )

                proc_priv = await conn.create_process(
                    ["bash", "-lc", get_priv_cmd]
                ).execute()
                priv_key = proc_priv.get_stdout().strip()

                if not priv_key:
                    raise RuntimeError(
                        f"Could not obtain NordLynx private key from nlx showconf on {container}"
                    )

                server_config["private_key"] = priv_key

            return

        wg_conf = (
            f"[Interface]\nPrivateKey = {server_config['private_key']}\nListenPort ="
            f" {server_config['port']}\nAddress = 100.64.0.1/10\n\n"
        )

        for node in node_list:
            wg_conf += generate_peer_config(
                node, ", ".join(cls.get_allowed_ip_list(node.ip_addresses))
            )

        cmd = (
            f"docker exec --privileged {server_config['container']} bash -c"
            f' \'echo "{wg_conf}" > /etc/wireguard/wg0.conf; wg-quick down'
            " /etc/wireguard/wg0.conf; wg-quick up /etc/wireguard/wg0.conf'"
        )
        ret = subprocess.run(
            cmd,
            shell=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        log.debug(
            "Executing %s on %s with result %s",
            cmd,
            server_config["container"],
            ret,
        )

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

            if ip_stack in [IPStack.IPv4, IPStack.IPv4v6]:
                self.assign_random_ip(node.id, IPProto.IPv4)

            if ip_stack in [IPStack.IPv6, IPStack.IPv4v6]:
                self.assign_random_ip(node.id, IPProto.IPv6)

        assert (len(node_configs) + current_node_list_len) == len(self.nodes)

        return tuple(list(self.nodes.values())[current_node_list_len:])

    async def prepare_vpn_servers(self, connections: Optional[List[Connection]] = None):
        for wg_server in WG_SERVERS:
            await self.setup_vpn_servers(
                list(self.nodes.values()), wg_server, connections
            )
