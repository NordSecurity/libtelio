import mesh_api
import platform
import pytest
from config import DERP_PRIMARY, DERP_FAKE
from mesh_api import Node, API
from utils.bindings import Config, Peer, PeerBase

if platform.machine() != "x86_64":
    import pure_wg as Key
else:
    from python_wireguard import Key  # type: ignore


class TestNode:
    def test_to_client_config(self) -> None:
        sk, pk = Key.key_pair()
        node = Node()
        node.name = "aa"
        node.id = "bb"
        node.private_key = sk
        node.public_key = pk

        expected = {"name": "aa", "id": "bb", "sk": sk, "pk": pk}
        assert node.to_client_config() == expected

    def test_to_peer_config(self) -> None:
        node = Node()
        node.id = "aa"
        node.public_key = "bb"
        node.hostname = "cc"
        node.ip_addresses = ["dd"]
        node.nickname = "ff"
        node.endpoints = ["ee"]

        expected = Peer(
            base=PeerBase(
                identifier="aa",
                public_key="bb",
                hostname="cc",
                ip_addresses=["dd"],
                nickname="ff",
            ),
            is_local=False,
            allow_incoming_connections=False,
            allow_peer_send_files=False,
            allow_multicast=True,
            peer_allows_multicast=True,
        )
        assert expected == node.to_peer_config_for_node(node)

        node = Node()
        node.is_local = True
        assert node.to_peer_config_for_node(node).is_local

        node = Node()

        node = Node()
        node.set_peer_firewall_settings(node.id, True)
        assert node.to_peer_config_for_node(node).allow_incoming_connections
        assert not node.to_peer_config_for_node(node).allow_peer_send_files


class TestMeshApi:
    def test_register_node(self) -> None:
        api = API()
        sk, pk = Key.key_pair()
        node = api.register(name="aa", node_id="bb", private_key=sk, public_key=pk)
        assert node.name == "aa"
        assert node.id == "bb"
        assert node.private_key == sk
        assert node.public_key == pk

    def test_register_duplicate_node(self) -> None:
        api = API()
        api.register(name="aa", node_id="bb", private_key="cc", public_key="dd")

        with pytest.raises(mesh_api.DuplicateNodeError) as e:
            api.register(name="aa", node_id="bb", private_key="cc", public_key="dd")

        assert e.value.node_id == "bb"

    def test_get_meshnet_config_missing_node(self) -> None:
        api = API()
        with pytest.raises(mesh_api.MissingNodeError) as e:
            api.get_meshnet_config(node_id="aa")
        assert e.value.node_id == "aa"

    def test_get_meshnet_config(self) -> None:
        api = API()

        sk_alpha, pk_alpha = Key.key_pair()

        alpha = api.register(
            name="alpha",
            node_id="id-alpha",
            private_key=sk_alpha,
            public_key=pk_alpha,
        )
        alpha.hostname = "aaa"
        alpha.ip_addresses = ["bbb"]
        alpha.endpoints = ["ccc"]
        alpha.nickname = "fff"

        beta = api.register(
            name="beta", node_id="id-beta", private_key="sk-beta", public_key="pk-beta"
        )

        meshnet_config = api.get_meshnet_config("id-alpha")

        expected = Config(
            this=PeerBase(
                identifier="id-alpha",
                public_key=pk_alpha,
                hostname="aaa",
                ip_addresses=["bbb"],
                nickname="fff",
            ),
            peers=[beta.to_peer_config_for_node(alpha)],
            derp_servers=mesh_api.DERP_SERVERS,
            dns=None,
        )

        assert meshnet_config == expected

    def test_get_meshnet_config_derp_servers(self):
        api = API()
        api.register(name="name", node_id="id", private_key="sk", public_key="pk")

        derp_servers = [DERP_FAKE, DERP_PRIMARY]
        meshnet_config = api.get_meshnet_config("id", derp_servers=derp_servers)
        assert meshnet_config.derp_servers == derp_servers

    def test_assign_ip_collision(self):
        api = API()
        api.register(name="name", node_id="id1", private_key="sk", public_key="pk")
        api.register(name="name", node_id="id2", private_key="sk", public_key="pk")
        api.assign_ip("id1", "0.0.0.0")
        with pytest.raises(mesh_api.AddressCollisionError) as e:
            api.assign_ip("id2", "0.0.0.0")
        assert e.value.node_id == "id1"

    def test_assign_ip(self):
        api = API()
        node1 = api.register(
            name="name", node_id="id1", private_key="sk", public_key="pk"
        )
        node2 = api.register(
            name="name", node_id="id2", private_key="sk", public_key="pk"
        )
        api.assign_ip("id1", "1.1.1.1")
        api.assign_ip("id2", "2.2.2.2")
        api.assign_ip("id2", "3.3.3.3")
        assert node1.ip_addresses == ["1.1.1.1"]
        assert node2.ip_addresses == ["2.2.2.2", "3.3.3.3"]

    def test_assign_nickname(self):
        api = API()
        alpha = api.register(
            name="alpha", node_id="id1", private_key="sk", public_key="pk"
        )
        beta = api.register(
            name="beta", node_id="id2", private_key="sk", public_key="pk"
        )

        api.assign_nickname("id1", "john")
        api.assign_nickname("id2", "jane")

        assert alpha.name == "alpha"
        assert beta.name == "beta"
        assert alpha.nickname == "john"
        assert beta.nickname == "jane"

        api.reset_nickname("id1")
        api.reset_nickname("id2")

        assert alpha.nickname is None
        assert beta.nickname is None

    def test_assign_invalid_nickname(self):
        api = API()
        alpha = api.register(
            name="alpha", node_id="id1", private_key="sk", public_key="pk"
        )

        with pytest.raises(mesh_api.NicknameInvalidError):
            api.assign_nickname("id1", None)
        with pytest.raises(mesh_api.NicknameInvalidError):
            api.assign_nickname("id1", "")
        with pytest.raises(mesh_api.NicknameInvalidError):
            api.assign_nickname("id1", "-john")
        with pytest.raises(mesh_api.NicknameInvalidError):
            api.assign_nickname("id1", "john-")
        with pytest.raises(mesh_api.NicknameInvalidError):
            api.assign_nickname("id1", "john doe")
        with pytest.raises(mesh_api.NicknameInvalidError):
            api.assign_nickname("id1", "johnsomethingsomethingsomething")
        with pytest.raises(mesh_api.NicknameInvalidError):
            api.assign_nickname("id1", "joh--n")
        with pytest.raises(mesh_api.NicknameCollisionError):
            api.assign_nickname("id1", "alpha")
        with pytest.raises(mesh_api.NicknameCollisionError):
            api.assign_nickname("id1", "alpha.nord")

        assert alpha.nickname is None

    def test_assign_duplicated_nickname(self):
        api = API()
        alpha = api.register(
            name="alpha", node_id="id1", private_key="sk", public_key="pk"
        )
        beta = api.register(
            name="beta", node_id="id2", private_key="sk", public_key="pk"
        )

        api.assign_nickname("id1", "john")
        with pytest.raises(mesh_api.NicknameCollisionError) as e:
            api.assign_nickname("id2", "john")

        assert e.value.node_id == "id1"
        assert alpha.nickname == "john"
        assert beta.nickname is None
