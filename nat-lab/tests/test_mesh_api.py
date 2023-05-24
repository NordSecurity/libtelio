import pytest
import mesh_api
from mesh_api import Node, API


class TestNode:
    def test_to_client_config(self) -> None:
        node = Node()
        node.name = "aa"
        node.id = "bb"
        node.private_key = "cc"
        node.public_key = "dd"

        expected = {
            "name": "aa",
            "id": "bb",
            "sk": "cc",
            "pk": "dd",
        }
        assert node.to_client_config() == expected

    def test_to_peer_config(self) -> None:
        node = Node()
        node.id = "aa"
        node.public_key = "bb"
        node.hostname = "cc"
        node.ip_addresses = ["dd"]
        node.endpoints = ["ee"]

        expected = {
            "identifier": "aa",
            "public_key": "bb",
            "hostname": "cc",
            "ip_addresses": ["dd"],
            "endpoints": ["ee"],
            "is_local": False,
            "allow_connections": False,
            "allow_incoming_connections": False,
            "allow_peer_send_files": False,
        }
        assert expected == node.to_peer_config_for_node(node)

        node = Node()
        node.is_local = True
        assert node.to_peer_config_for_node(node)["is_local"] == True

        node = Node()
        node.allow_connections = True
        assert node.to_peer_config_for_node(node)["allow_connections"] == True

        node = Node()
        node.set_peer_firewall_settings(node.id, True)
        assert node.to_peer_config_for_node(node)["allow_incoming_connections"] == True
        assert node.to_peer_config_for_node(node)["allow_peer_send_files"] == False


class TestMeshApi:
    def test_register_node(self) -> None:
        api = API()
        node = api.register(name="aa", id="bb", private_key="cc", public_key="dd")
        assert node.name == "aa"
        assert node.id == "bb"
        assert node.private_key == "cc"
        assert node.public_key == "dd"

    def test_register_duplicate_node(self) -> None:
        api = API()
        api.register(name="aa", id="bb", private_key="cc", public_key="dd")

        with pytest.raises(mesh_api.DuplicateNodeError) as e:
            api.register(name="aa", id="bb", private_key="cc", public_key="dd")

        assert e.value.node_id == "bb"

    def test_get_meshmap_missing_node(self) -> None:
        api = API()
        with pytest.raises(mesh_api.MissingNodeError) as e:
            meshmap = api.get_meshmap(id="aa")
        assert e.value.node_id == "aa"

    def test_get_meshmap(self) -> None:
        api = API()

        alpha = api.register(
            name="alpha", id="id-alpha", private_key="sk-alpha", public_key="pk-alpha"
        )
        alpha.hostname = "aaa"
        alpha.ip_addresses = ["bbb"]
        alpha.endpoints = ["ccc"]

        beta = api.register(
            name="beta", id="id-beta", private_key="sk-beta", public_key="pk-beta"
        )

        meshmap = api.get_meshmap("id-alpha")

        expected = {
            "identifier": "id-alpha",
            "public_key": "pk-alpha",
            "hostname": "aaa",
            "ip_addresses": ["bbb"],
            "endpoints": ["ccc"],
            "peers": [
                beta.to_peer_config_for_node(alpha),
            ],
            "derp_servers": mesh_api.DERP_SERVERS,
        }
        assert meshmap == expected

    def test_get_meshmap_derp_servers(self):
        api = API()
        api.register(name="name", id="id", private_key="sk", public_key="pk")

        derp_servers = [
            {
                "aaa": "bbb",
            }
        ]
        meshmap = api.get_meshmap("id", derp_servers=derp_servers)
        assert meshmap["derp_servers"] == derp_servers

    def test_assign_ip_collision(self):
        api = API()
        api.register(name="name", id="id1", private_key="sk", public_key="pk")
        api.register(name="name", id="id2", private_key="sk", public_key="pk")
        api.assign_ip("id1", "0.0.0.0")
        with pytest.raises(mesh_api.AddressCollisionError) as e:
            api.assign_ip("id2", "0.0.0.0")
        assert e.value.node_id == "id1"

    def test_assign_ip(self):
        api = API()
        node1 = api.register(name="name", id="id1", private_key="sk", public_key="pk")
        node2 = api.register(name="name", id="id2", private_key="sk", public_key="pk")
        api.assign_ip("id1", "1.1.1.1")
        api.assign_ip("id2", "2.2.2.2")
        api.assign_ip("id2", "3.3.3.3")
        assert node2.ip_addresses == ["2.2.2.2", "3.3.3.3"]
