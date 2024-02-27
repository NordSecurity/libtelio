from hashlib import md5
from typing import List, Optional, Any
from utils import testing

DERP_BIT = 0b00000001
WG_BIT = 0b00000010
IPV4_BIT = 0b00000100
IPV6_BIT = 0b00001000


# Add external peers to peers list
#
# External links can have two forms:
#     - "vpn":md5(server_ip):<state>
#     - <meshnet_id>:<node_fingerprint>:<state>
# For convenience, vpn node is always identified by "vpn" string, other nodes by their fingerprint
def process_external_peers(event, peers):
    if event.external_links != "":
        external_links = event.external_links.split(",")
        for link in external_links:
            external_peer_fp = (
                link.split(":")[0]
                if link.split(":")[0] == "vpn"
                else link.split(":")[1]
            )
            peers.append(external_peer_fp)


class ExistanceValidator:
    def validate(self, value):
        return (value is not None) and (value != "")


class InexistanceValidator:
    def validate(self, value):
        return (value is None) or (value == "")


class StringEqualsValidator:
    def __init__(self, value):
        self._value = value

    def validate(self, value):
        return self._value == value


class StringContainmentValidator:
    def __init__(self, value, contains=True):
        self._value = value
        self._contains = contains

    def validate(self, value):
        if self._contains:
            return self._value in value
        return not self._value in value


class StringOccurrencesValidator:
    def __init__(self, value, count):
        self._value = value
        self._count = count

    def validate(self, value):
        return value.count(self._value) == self._count


class IntegerEqualsValidator:
    def __init__(self, value):
        self._value = value

    def validate(self, value):
        return self._value == value


class IntegerNotEqualsValidator:
    def __init__(self, value):
        self._value = value

    def validate(self, value):
        return self._value != value


class ConnectionCountValidator:
    def __init__(self, count):
        self._count = count

    def validate(self, value):
        connections = value.split(",")
        return len(connections) == self._count


class ConnectionStateValidator:
    def __init__(self, all_connections_up, expected_states: Optional[List[int]] = None):
        self._all_connections_up = all_connections_up
        self._expected_states = expected_states

    def validate(self, value):
        # Each connection is separated by a ',':
        # [########connection1#########, ########connection2#########]
        connections = value.split(",")
        # It consists in three info-values separated each by ':' and
        # the connection_state will always be the last one:
        # [info1:info2:connection_state, info1:info2:connection_state]
        if self._all_connections_up:
            return not any(conn.split(":")[2] == "0" for conn in connections)
        if self._expected_states is not None:
            states = testing.unpack_optional(self._expected_states)
            return all(
                int(conn.split(":")[2]) & states[index]
                for index, conn in enumerate(connections)
            )
        return False


class StringValidator:
    def __init__(
        self,
        exists=True,
        equals="",
        contains: Optional[List[str]] = None,
        does_not_contain: Optional[List[str]] = None,
    ):
        self._validators: List[Any] = []

        if exists:
            self._validators.append(ExistanceValidator())
        else:
            self._validators.append(InexistanceValidator())
            return

        if equals != "":
            self._validators.append(StringEqualsValidator(value=equals))

        if contains:
            for substring in contains:
                self._validators.append(
                    StringContainmentValidator(value=substring, contains=True)
                )

        if does_not_contain:
            for substring in does_not_contain:
                self._validators.append(
                    StringContainmentValidator(value=substring, contains=False)
                )

    def validate(self, value):
        for v in self._validators:
            if not v.validate(value):
                return False
        return True


class NameValidator:
    def __init__(self, name=""):
        self._validator = StringValidator(equals=name)

    def validate(self, event):
        return self._validator.validate(event.name)


class CategoryValidator:
    def __init__(self, category=""):
        self._validator = StringValidator(equals=category)

    def validate(self, event):
        return self._validator.validate(event.category)


class ExternalLinksValidator:
    def __init__(
        self,
        exists=True,
        equals="",
        contains: Optional[List[str]] = None,
        does_not_contain: Optional[List[str]] = None,
        all_connections_up=False,
        no_of_connections=0,
        no_of_vpn=0,
        expected_states: Optional[List[int]] = None,
    ):
        self._validators: List[Any] = [
            StringValidator(
                exists=exists,
                equals=equals,
                contains=contains,
                does_not_contain=does_not_contain,
            )
        ]

        if exists:
            if all_connections_up or expected_states is not None:
                self._validators.append(
                    ConnectionStateValidator(
                        all_connections_up=all_connections_up,
                        expected_states=expected_states,
                    )
                )
            if no_of_connections != 0:
                self._validators.append(
                    ConnectionCountValidator(count=no_of_connections)
                )

            self._validators.append(
                StringOccurrencesValidator(value="vpn", count=no_of_vpn)
            )

    def validate(self, event):
        for v in self._validators:
            if not v.validate(event.external_links):
                return False
        return True


class ConnectivityMatrixValidator:
    def __init__(
        self,
        exists=True,
        no_of_connections=0,
        all_connections_up=False,
        expected_states: Optional[List[int]] = None,
    ):
        self._validators: List[Any] = [StringValidator(exists=exists)]  # type: ignore
        if exists:
            if no_of_connections != 0:
                self._validators.append(
                    ConnectionCountValidator(count=no_of_connections)
                )
            if all_connections_up or expected_states is not None:
                self._validators.append(
                    ConnectionStateValidator(
                        all_connections_up=all_connections_up,
                        expected_states=expected_states,
                    )
                )

    def validate(self, event):
        for v in self._validators:
            if not v.validate(event.connectivity_matrix):
                return False
        return True


class FingerprintValidator:
    def __init__(self, exists=True, equals=""):
        self._validator = StringValidator(exists=exists, equals=equals)

    def validate(self, event):
        return self._validator.validate(event.fp)


class MembersValidator:
    def __init__(
        self,
        exists=True,
        equals="",
        contains: Optional[List[str]] = None,
        does_not_contain: Optional[List[str]] = None,
    ):
        self._validator = StringValidator(
            exists=exists,
            equals=equals,
            contains=contains,
            does_not_contain=does_not_contain,
        )

    def validate(self, event):
        return self._validator.validate(event.members)


class ConnectionDurationValidator:
    def __init__(self, exists=True):
        self._validator = StringValidator(exists=exists)

    def validate(self, event):
        return self._validator.validate(event.connection_duration)


class HeartbeatIntervalValidator:
    def __init__(self, value, equals=True):
        if equals:
            self._validator = IntegerEqualsValidator(value)
        else:
            self._validator = IntegerNotEqualsValidator(value)

    def validate(self, event):
        return self._validator.validate(event.heartbeat_interval)


class RttValidator:
    def __init__(
        self,
        exists=True,
        members: Optional[List[str]] = None,
        equals="",
        contains: Optional[List[str]] = None,
        does_not_contain: Optional[List[str]] = None,
    ):
        self._members = members
        if not members:
            self._validator = StringValidator(exists=exists)
        else:
            self._validator = StringValidator(
                exists=exists,
                equals=equals,
                contains=contains,
                does_not_contain=does_not_contain,
            )

    def validate(self, event):
        if not self._members:
            return self._validator.validate(event.rtt)

        rtt_list = event.rtt.split(",")
        peers = event.members.split(",")
        process_external_peers(event, peers)

        peers_rtt = dict(zip(peers, rtt_list))

        for member in self._members:
            rtt = peers_rtt.get(member)
            if rtt:
                assert self._validator.validate(rtt), member
            else:
                assert False, member
        return True


class RttLossValidator:
    def __init__(
        self,
        exists=True,
        members: Optional[List[str]] = None,
        equals="",
        contains: Optional[List[str]] = None,
        does_not_contain: Optional[List[str]] = None,
    ):
        self._members = members
        if not members:
            self._validator = StringValidator(exists=exists)
        else:
            self._validator = StringValidator(
                exists=exists,
                equals=equals,
                contains=contains,
                does_not_contain=does_not_contain,
            )

    def validate(self, event):
        if not self._members:
            return self._validator.validate(event.rtt_loss)

        rtt_loss_list = event.rtt_loss.split(",")
        peers = event.members.split(",")
        process_external_peers(event, peers)

        peers_rtt_loss = dict(zip(peers, rtt_loss_list))

        for member in self._members:
            rtt_loss = peers_rtt_loss.get(member)
            if rtt_loss:
                assert self._validator.validate(rtt_loss), member
            else:
                assert False, member
        return True


class Rtt6Validator:
    def __init__(
        self,
        exists=True,
        members: Optional[List[str]] = None,
        equals="",
        contains: Optional[List[str]] = None,
        does_not_contain: Optional[List[str]] = None,
    ):
        self._members = members
        if not members:
            self._validator = StringValidator(exists=exists)
        else:
            self._validator = StringValidator(
                exists=exists,
                equals=equals,
                contains=contains,
                does_not_contain=does_not_contain,
            )

    def validate(self, event):
        if not self._members:
            return self._validator.validate(event.rtt6)

        rtt6_list = event.rtt6.split(",")
        peers = event.members.split(",")
        process_external_peers(event, peers)

        peers_rtt6 = dict(zip(peers, rtt6_list))

        for member in self._members:
            rtt6 = peers_rtt6.get(member)
            if rtt6:
                assert self._validator.validate(rtt6), member
            else:
                assert False, member
        return True


class Rtt6LossValidator:
    def __init__(
        self,
        exists=True,
        members: Optional[List[str]] = None,
        equals="",
        contains: Optional[List[str]] = None,
        does_not_contain: Optional[List[str]] = None,
    ):
        self._members = members
        if not members:
            self._validator = StringValidator(exists=exists)
        else:
            self._validator = StringValidator(
                exists=exists,
                equals=equals,
                contains=contains,
                does_not_contain=does_not_contain,
            )

    def validate(self, event):
        if not self._members:
            return self._validator.validate(event.rtt6_loss)

        rtt6_loss_list = event.rtt6_loss.split(",")
        peers = event.members.split(",")
        process_external_peers(event, peers)

        peers_rtt6_loss = dict(zip(peers, rtt6_loss_list))

        for member in self._members:
            rtt6_loss = peers_rtt6_loss.get(member)
            if rtt6_loss:
                assert self._validator.validate(rtt6_loss), member
            else:
                assert False, member
        return True


class SentDataValidator:
    def __init__(
        self,
        exists=True,
        members: Optional[List[str]] = None,
        equals="",
        contains: Optional[List[str]] = None,
        does_not_contain: Optional[List[str]] = None,
    ):
        self._members = members
        if not members:
            self._validator = StringValidator(exists=exists)
        else:
            self._validator = StringValidator(
                exists=exists,
                equals=equals,
                contains=contains,
                does_not_contain=does_not_contain,
            )

    def validate(self, event):
        if not self._members:
            return self._validator.validate(event.sent_data)

        sent_data_list = event.sent_data.split(",")
        peers = event.members.split(",")
        process_external_peers(event, peers)

        peers_sent_data = dict(zip(peers, sent_data_list))

        for member in self._members:
            sent_data = peers_sent_data.get(member)
            if sent_data:
                assert self._validator.validate(sent_data), member
            else:
                assert False, member
        return True


class ReceivedDataValidator:
    def __init__(
        self,
        exists=True,
        members: Optional[List[str]] = None,
        equals="",
        contains: Optional[List[str]] = None,
        does_not_contain: Optional[List[str]] = None,
    ):
        self._members = members
        if not members:
            self._validator = StringValidator(exists=exists)
        else:
            self._validator = StringValidator(
                exists=exists,
                equals=equals,
                contains=contains,
                does_not_contain=does_not_contain,
            )

    def validate(self, event):
        if not self._members:
            return self._validator.validate(event.received_data)

        received_data_list = event.received_data.split(",")
        peers = event.members.split(",")
        process_external_peers(event, peers)

        peers_received_data = dict(zip(peers, received_data_list))

        for member in self._members:
            received_data = peers_received_data.get(member)
            if received_data:
                assert self._validator.validate(received_data), member
            else:
                assert False, member
        return True


class NatTraversalConnInfoValidator:
    def __init__(
        self,
        exists=True,
        members: Optional[List[str]] = None,
        equals="",
        contains: Optional[List[str]] = None,
        does_not_contain: Optional[List[str]] = None,
    ):
        self._members = members
        if not members:
            self._validator = StringValidator(exists=exists)
        else:
            self._validator = StringValidator(
                exists=exists,
                equals=equals,
                contains=contains,
                does_not_contain=does_not_contain,
            )

    def validate(self, event):
        if not self._members:
            return self._validator.validate(event.nat_traversal_conn_info)

        nat_traversal_conn_info_list = event.nat_traversal_conn_info.split(",")
        peers = event.members.split(",")
        process_external_peers(event, peers)

        peers_nat_traversal_conn_info = dict(zip(peers, nat_traversal_conn_info_list))

        for member in self._members:
            nat_traversal_conn_info = peers_nat_traversal_conn_info.get(member)
            if nat_traversal_conn_info:
                assert self._validator.validate(nat_traversal_conn_info), member
            else:
                assert False, member
        return True


class DerpConnInfoValidator:
    def __init__(
        self,
        exists=True,
        servers: Optional[List[str]] = None,
        equals="",
        contains: Optional[List[str]] = None,
        does_not_contain: Optional[List[str]] = None,
    ):
        self._servers = servers
        if not servers:
            self._validator = StringValidator(exists=exists)
        else:
            self._validator = StringValidator(
                exists=exists,
                equals=equals,
                contains=contains,
                does_not_contain=does_not_contain,
            )

    def validate(self, event):
        if not self._servers:
            return self._validator.validate(event.derp_conn_info)

        derp_conn_info_list = event.derp_conn_info.split(",")
        servers_encoded_list = []

        for derp_conn_info in derp_conn_info_list:
            servers_encoded_list.append(derp_conn_info.split(":")[0])

        for server in self._servers:
            server_encoded = md5(server.encode()).hexdigest()
            if server_encoded not in servers_encoded_list:
                assert False, server
            else:
                break

        for derp_conn_info in derp_conn_info_list:
            if derp_conn_info:
                assert self._validator.validate(derp_conn_info), derp_conn_info

        return True


class NatTypeValidator:
    def __init__(self, value):
        self._validator = StringValidator(equals=value)

    def validate(self, event):
        return self._validator.validate(event.nat_type)


class MemNatTypeValidator:
    def __init__(self, value):
        self._validators = []
        for v in value:
            self._validators.append(StringValidator(equals=v))

    def validate(self, event):
        for v, e in zip(self._validators, event.mem_nat_types.split(",")):
            if not v.validate(e):
                return False
        return True


class EventValidator:
    def __init__(self, node_fingerprint):
        self._validators = []
        self.node_fingerprint = node_fingerprint

    def add_name_validator(self, name=""):
        self._validators.append(NameValidator(name=name))
        return self

    def add_category_validator(self, category=""):
        self._validators.append(CategoryValidator(category=category))
        return self

    def add_external_links_validator(
        self,
        exists=True,
        equals="",
        contains: Optional[List[str]] = None,
        does_not_contain: Optional[List[str]] = None,
        all_connections_up=False,
        no_of_connections=0,
        no_of_vpn=0,
        expected_states: Optional[List[int]] = None,
    ):
        self._validators.append(
            ExternalLinksValidator(
                exists=exists,
                equals=equals,
                contains=contains,
                does_not_contain=does_not_contain,
                all_connections_up=all_connections_up,
                no_of_connections=no_of_connections,
                no_of_vpn=no_of_vpn,
                expected_states=expected_states,
            )
        )
        return self

    def add_connectivity_matrix_validator(
        self,
        exists=True,
        no_of_connections=0,
        all_connections_up=False,
        expected_states: Optional[List[int]] = None,
    ):
        self._validators.append(
            ConnectivityMatrixValidator(
                exists,
                no_of_connections=no_of_connections,
                all_connections_up=all_connections_up,
                expected_states=expected_states,
            )
        )
        return self

    def add_fingerprint_validator(self, exists=True, equals=""):
        self._validators.append(FingerprintValidator(exists=exists, equals=equals))
        return self

    def add_members_validator(
        self,
        exists=True,
        equals="",
        contains: Optional[List[str]] = None,
        does_not_contain: Optional[List[str]] = None,
    ):
        self._validators.append(
            MembersValidator(
                exists=exists,
                equals=equals,
                contains=contains,
                does_not_contain=does_not_contain,
            )
        )
        return self

    def add_connection_duration_validator(self, exists=True):
        self._validators.append(ConnectionDurationValidator(exists=exists))
        return self

    def add_heartbeat_interval_validator(self, value, equals=True):
        self._validators.append(HeartbeatIntervalValidator(value=value, equals=equals))
        return self

    def add_rtt_validator(
        self,
        exists=True,
        members: Optional[List[str]] = None,
        equals="",
        contains: Optional[List[str]] = None,
        does_not_contain: Optional[List[str]] = None,
    ):
        self._validators.append(
            RttValidator(
                exists,
                members,
                equals,
                contains,
                does_not_contain,
            )
        )
        return self

    def add_rtt_loss_validator(
        self,
        exists=True,
        members: Optional[List[str]] = None,
        equals="",
        contains: Optional[List[str]] = None,
        does_not_contain: Optional[List[str]] = None,
    ):
        self._validators.append(
            RttLossValidator(
                exists,
                members,
                equals,
                contains,
                does_not_contain,
            )
        )
        return self

    def add_rtt6_validator(
        self,
        exists=True,
        members: Optional[List[str]] = None,
        equals="",
        contains: Optional[List[str]] = None,
        does_not_contain: Optional[List[str]] = None,
    ):
        self._validators.append(
            Rtt6Validator(
                exists,
                members,
                equals,
                contains,
                does_not_contain,
            )
        )
        return self

    def add_rtt6_loss_validator(
        self,
        exists=True,
        members: Optional[List[str]] = None,
        equals="",
        contains: Optional[List[str]] = None,
        does_not_contain: Optional[List[str]] = None,
    ):
        self._validators.append(
            Rtt6LossValidator(
                exists,
                members,
                equals,
                contains,
                does_not_contain,
            )
        )
        return self

    def add_sent_data_validator(
        self,
        exists=True,
        members: Optional[List[str]] = None,
        equals="",
        contains: Optional[List[str]] = None,
        does_not_contain: Optional[List[str]] = None,
    ):
        self._validators.append(
            SentDataValidator(
                exists,
                members,
                equals,
                contains,
                does_not_contain,
            )
        )
        return self

    def add_received_data_validator(
        self,
        exists=True,
        members: Optional[List[str]] = None,
        equals="",
        contains: Optional[List[str]] = None,
        does_not_contain: Optional[List[str]] = None,
    ):
        self._validators.append(
            ReceivedDataValidator(
                exists,
                members,
                equals,
                contains,
                does_not_contain,
            )
        )
        return self

    def add_nat_traversal_conn_info_validator(
        self,
        exists=True,
        members: Optional[List[str]] = None,
        equals="",
        contains: Optional[List[str]] = None,
        does_not_contain: Optional[List[str]] = None,
    ):
        self._validators.append(
            NatTraversalConnInfoValidator(
                exists,
                members,
                equals,
                contains,
                does_not_contain,
            )
        )
        return self

    def add_derp_conn_info_validator(
        self,
        exists=True,
        servers: Optional[List[str]] = None,
        equals="",
        contains: Optional[List[str]] = None,
        does_not_contain: Optional[List[str]] = None,
    ):
        self._validators.append(
            DerpConnInfoValidator(
                exists,
                servers,
                equals,
                contains,
                does_not_contain,
            )
        )
        return self

    def add_nat_type_validators(
        self, is_nat_type_collection_enabled: bool, nat_type: str, nat_mem: List[str]
    ):
        if is_nat_type_collection_enabled:
            self.add_self_nat_validator(value=nat_type)
            self.add_members_nat_validator(value=nat_mem)
        return self

    def add_self_nat_validator(self, value):
        self._validators.append(NatTypeValidator(value))
        return self

    def add_members_nat_validator(self, value):
        self._validators.append(MemNatTypeValidator(value))
        return self

    def validate(self, event) -> tuple[bool, str]:
        for validator in self._validators:
            if not validator.validate(event):
                return False, type(validator).__name__
        return True, ""


def basic_validator(
    node_fingerprint: str, heartbeat_interval: int = 3600, meshnet_id: str = ""
) -> EventValidator:
    event_validator = (
        EventValidator(node_fingerprint)
        .add_name_validator("heartbeat")
        .add_category_validator("service_quality")
        .add_fingerprint_validator(exists=True, equals=meshnet_id)
        .add_heartbeat_interval_validator(value=heartbeat_interval, equals=True)
        .add_connection_duration_validator(exists=True)
    )
    if node_fingerprint != "":
        # Current node should always be in the members list
        event_validator.add_members_validator(exists=True, contains=[node_fingerprint])

    return event_validator
