#!/usr/bin/env python3

import os
import sys
import yaml
from collections import namedtuple
from dataclasses import dataclass
from enum import Enum

# This script parses a docker-compose.yml file and generates a network topology diagram in mermaid format.

NodeTypeData = namedtuple("NodeTypeData", ["shape_l", "shape_r"])


class NodeType(Enum):
    NODE = NodeTypeData("(", ")")
    CLIENT = NodeTypeData("(", ")")
    GATEWAY = NodeTypeData("([", "])")
    SERVER = NodeTypeData("[[", "]]")


# @dataclass
class Node:
    def __init__(
        self, name: str, addresses: list[str], gateways: list[str], is_gateway: bool
    ):
        self.name = name
        self.addresses = addresses
        self.gateways = gateways
        self.is_gateway = is_gateway

    def __repr__(self):
        return f"{self.name}: addresses: {self.addresses} gateways: {self.gateways} is_gateway: {self.is_gateway}"


@dataclass
class Network:
    def __init__(self, subnets: list[str]):
        self.nodes: list[Node] = []
        self.subnets = subnets

    def __repr__(self):
        return f"subnets: {self.subnets} nodes: {self.nodes}"

    def add_node(self, node: Node):
        self.nodes.append(node)


def parse_docker_compose(compose_file):
    with open(compose_file, "r", encoding="utf-8") as file:
        compose_content = yaml.safe_load(file)

    # parse networks
    networks_data = compose_content.get("networks", [])
    networks = {}
    for network_name, network in networks_data.items():
        ipam = network.get("ipam", {})
        config = ipam.get("config", [])
        subnets = [entry.get("subnet") for entry in config]
        networks[network_name] = Network(subnets)

    # parse services and add to respective network
    services_data = compose_content.get("services", {})
    for service_name, service in services_data.items():
        service_networks = service.get("networks", {})
        environment = service.get("environment", {})

        # parse gateway values for node
        gateways = []
        if environment:
            for env_key, env_value in environment.items():
                if "GATEWAY" in env_key:
                    if not "none" in env_value:
                        gateways.append(env_value)

        node_addresses = []
        for network_name, network_info in service_networks.items():
            ip_addresses = []
            if isinstance(network_info, dict):
                ipv4 = network_info.get("ipv4_address")
                if ipv4:
                    ip_addresses.append(ipv4)
                    node_addresses.append(ipv4)
                ipv6 = network_info.get("ipv6_address")
                if ipv6:
                    ip_addresses.append(ipv6)
                    node_addresses.append(ipv6)

            is_gateway = "gw" in service_name
            node = Node(service_name, node_addresses, gateways, is_gateway)

            # add node to it's respective networks, unless it's gateways
            if not ("internet" in network_name and is_gateway):
                networks[network_name].add_node(node)

    return networks


def extract_services(networks: dict):
    clients = {}
    gateways = {}
    for network in networks.values():
        for node in network.nodes:
            if node.is_gateway:
                gateways[node.name] = node
            if len(node.gateways) > 0:
                clients[node.name] = node
    return clients, gateways


def generate_diagram(networks):
    diagram = "graph LR\n"
    diagram += "%% AUTO GENERATED DIAGRAM. To update run `./utils/generate_network_diagram.py docker-compose.yml network.md`\n\n"

    clients, gateways = extract_services(networks)

    # re-arrange cone-05 network
    cone_net5 = networks.pop("cone-net-05")
    networks_list = list(networks.items())
    networks_list.insert(1, ("cone-net-05", cone_net5))

    # Networks
    diagram += "%% Networks"
    for network_name, network in networks_list:
        diagram += f"\n  %% Network {network_name}\n"
        diagram += f"  subgraph {network_name}[{network_name}]\n"
        diagram += "  direction LR\n"
        for node in network.nodes:
            # re-arrange some nodes to make it look better
            if not (
                ("cone-net-01" == network_name and "shared-client-01" == node.name)
                or (
                    "hsymmetric-net-01" == network_name
                    and "internal-symmetric-gw-01" == node.name
                )
            ):
                diagram += node_code(node)
        diagram += "  end\n"

    # Connections
    diagram += "\n  %% Node Connections\n"
    # Gateway connections
    for gateway in gateways.values():
        if len(gateway.gateways) == 0:
            diagram += f"  {gateway.name} -..- internet\n"

    # Client connections
    for client in clients.values():
        client_gateways = client.gateways
        for gateway in client_gateways:
            gateway_name = get_gateway_name(gateway, gateways)
            if "gw" in client.name:
                diagram += f"  {client.name} -..- {gateway_name}\n"
            else:
                diagram += f"  {client.name} -.- {gateway_name}\n"

    # Add vagrant boxes
    diagram += "\n  %% Vagrant boxes\n"
    diagram += "  subgraph vagrant\n"
    diagram += '    vm-boxes("vm-boxes\n        10.55.0.0/24 \n        10.66.0.0/24")\n'
    diagram += "  end\n"
    diagram += "  vm-boxes -.- cone-gw-03\n"
    diagram += "  vm-boxes -.- cone-gw-04\n"

    return diagram


def get_gateway_name(gateway_address, gateways) -> str:
    for gateway in gateways.values():
        if gateway_address in gateway.addresses:
            return gateway.name
    return "none"


def node_code(node: Node) -> str:
    indentation = 4
    node_type = NodeType.NODE
    if "client" in node.name:
        node_type = NodeType.CLIENT
    elif "server" in node.name:
        node_type = NodeType.SERVER
    elif "gw" in node.name:
        node_type = NodeType.GATEWAY

    node_str = " " * indentation
    node_str += f"{node.name}"
    node_str += node_type.value.shape_l
    node_str += '"'
    node_str += f"{node.name}"
    for addr in node.addresses:
        node_str += "\n" + "  " * indentation + f"{addr}"
    node_str += '"'
    node_str += node_type.value.shape_r
    node_str += "\n"
    return node_str


def main(compose_file, output_file):
    network = parse_docker_compose(compose_file)
    diagram = generate_diagram(network)

    with open(output_file, "w", encoding="utf-8") as file:
        file.write("```mermaid\n")
        file.write(diagram)
        file.write("```\n")
    print(f"Diagram saved at {output_file}")


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("usage: generate_network_diagram.py <docker_compose_file> <output_file>")
        sys.exit(1)

    compose_file_arg = sys.argv[1]
    output_file_arg = sys.argv[2]
    if not os.path.isfile(compose_file_arg):
        print(f"File not found: {compose_file_arg}")
        sys.exit(1)
    main(compose_file_arg, output_file_arg)
