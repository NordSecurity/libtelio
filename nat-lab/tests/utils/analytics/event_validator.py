import base64
from abc import ABC, abstractmethod
from hashlib import md5
from tests.helpers import connectivity_stack
from tests.utils import testing
from tests.utils.router import IPStack
from typing import List, Optional, Type
from typing_extensions import Self

DERP_BIT = 0b00000001
WG_BIT = 0b00000010
IPV4_BIT = 0b00000100
IPV6_BIT = 0b00001000

ALPHA_FINGERPRINT = "alpha_fingerprint"
BETA_FINGERPRINT = "beta_fingerprint"
GAMMA_FINGERPRINT = "gamma_fingerprint"
NODES_FINGERPRINTS = [ALPHA_FINGERPRINT, BETA_FINGERPRINT, GAMMA_FINGERPRINT]


class Validator(ABC):
    @abstractmethod
    def validate(self, value) -> bool:
        pass


##################################################################################
#                                BASIC VALIDATORS                                #
##################################################################################
class ExistanceValidator(Validator):
    def validate(self, value):
        return value is not None and value != ""


class InexistanceValidator(Validator):
    def validate(self, value):
        return value is None or value == ""


class StringEqualsValidator(Validator):
    def __init__(self, value):
        self._value = value

    def validate(self, value):
        return self._value == value


class StringContainmentValidator(Validator):
    def __init__(self, value, contains=True):
        self._value = value
        self._contains = contains

    def validate(self, value):
        if self._contains:
            return self._value in value
        return self._value not in value


class StringOccurrencesValidator(Validator):
    def __init__(self, value, count):
        self._value = value
        self._count = count

    def validate(self, value):
        return value.count(self._value) == self._count


class IntegerEqualityValidator(Validator):
    def __init__(self, value, equality: bool = True):
        self._value = value
        self._equality = equality

    def validate(self, value):
        if self._equality:
            return self._value == value
        return self._value != value


class StringValidator(Validator):
    def __init__(
        self,
        exists=True,
        equals="",
        contains: Optional[List[str]] = None,
        does_not_contain: Optional[List[str]] = None,
    ):
        self._validators: List[Validator] = []

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


##################################################################################
#                               SPECIFIC VALIDATORS                              #
##################################################################################
class ConnectionCountValidator(Validator):
    def __init__(self, count):
        self._count = count

    def validate(self, value):
        connections = value.split(",")
        return len(connections) == self._count


class ConnectionStateValidator(Validator):
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


class NameValidator(Validator):
    def __init__(self, name):
        self._validator = StringValidator(equals=name)

    def validate(self, value):
        return self._validator.validate(value.name)


class CategoryValidator(Validator):
    def __init__(self, category):
        self._validator = StringValidator(equals=category)

    def validate(self, value):
        return self._validator.validate(value.category)


class FingerprintValidator(Validator):
    def __init__(self, exists=True, equals=""):
        self._validator = StringValidator(exists=exists, equals=equals)

    def validate(self, value):
        return self._validator.validate(value.fp)


class ConnectionDurationValidator(Validator):
    def __init__(self, exists=True):
        self._validator = StringValidator(exists=exists)

    def validate(self, value):
        return self._validator.validate(value.connection_duration)


class HeartbeatIntervalValidator(Validator):
    def __init__(self, value, equals=True):
        self._validator = IntegerEqualityValidator(value, equals)

    def validate(self, value):
        return self._validator.validate(value.heartbeat_interval)


class MembersValidator(Validator):
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

    def validate(self, value):
        return self._validator.validate(value.members)


class NatTraversalConnInfoValidator(Validator):
    def __init__(
        self,
        self_pubkey: str,
        remote_pubkey: str,
        symmetric: bool,
        equals="",
        contains: Optional[List[str]] = None,
        does_not_contain: Optional[List[str]] = None,
        count=0,  # Expected number of nat traversal entries in the list
    ):
        self._count = count
        self._exists = (
            base64.b64decode(self_pubkey) < base64.b64decode(remote_pubkey)
            and not symmetric
        )
        self._validator = StringValidator(
            exists=self._exists,
            equals=equals,
            contains=contains,
            does_not_contain=does_not_contain,
        )

    def validate(self, value):
        if self._count == 0:
            return self._validator.validate(value.nat_traversal_conn_info)

        if self._exists and self._count > 0:
            nat_traversal_conn_info_list_len = len(
                value.nat_traversal_conn_info.split(",")
            )
            assert (
                nat_traversal_conn_info_list_len == self._count
            ), nat_traversal_conn_info_list_len
            return self._validator.validate(value.nat_traversal_conn_info)
        return True


class DerpConnInfoValidator(Validator):
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

    def validate(self, value):
        if not self._servers:
            return self._validator.validate(value.derp_conn_info)

        derp_conn_info_list = value.derp_conn_info.split(",")
        servers_encoded_list = [
            derp_conn_info.split(":")[0] for derp_conn_info in derp_conn_info_list
        ]

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


##################################################################################
#                              AGGREGATE VALIDATORS                              #
##################################################################################
class EventValidator(Validator):
    def __init__(self, node_fingerprint: str = ""):
        self._validators: List[Validator] = []
        self._node_fingerprint: str = node_fingerprint

    @classmethod
    def new_with_basic_validators(
        cls: Type[Self],
        node_fingerprint: str,
        heartbeat_interval: int = 3600,
        meshnet_id: str = "",
    ) -> Self:
        agg_validator = cls()
        agg_validator._node_fingerprint = node_fingerprint
        agg_validator._validators = [
            NameValidator("heartbeat"),
            CategoryValidator("service_quality"),
            FingerprintValidator(exists=True, equals=meshnet_id),
            HeartbeatIntervalValidator(value=heartbeat_interval, equals=True),
            ConnectionDurationValidator(exists=True),
            MembersValidator(exists=True, contains=[node_fingerprint]),
        ]
        return agg_validator

    def add_validator(self, validator: Validator) -> Self:
        self._validators.append(validator)
        return self

    def add_validator_list(self, validators: List[Validator]) -> Self:
        for validator in validators:
            self.add_validator(validator)
        return self

    def add_rtt_validators(
        self,
        ip_stacks: List[Optional[IPStack]],
    ) -> Self:
        node_ip_stacks = dict(zip(NODES_FINGERPRINTS, ip_stacks))
        primary_node_ip_stack = node_ip_stacks.pop(self.get_node_fingerprint())

        for fingerprint in node_ip_stacks:
            secondary_node_ip_stack = node_ip_stacks.get(fingerprint)

            if (
                secondary_node_ip_stack is not None
                and primary_node_ip_stack is not None
            ):
                (
                    rtt_c,
                    rtt_dnc,
                    rtt_loss_c,
                    rtt_loss_dnc,
                    rtt6_c,
                    rtt6_dnc,
                    rtt6_loss_c,
                    rtt6_loss_dnc,
                ) = (None, None, None, None, None, None, None, None)
                rtt_eq, rtt_loss_eq, rtt6_eq, rtt6_loss_eq = "", "", "", ""

                conn_stack = connectivity_stack(
                    primary_node_ip_stack, secondary_node_ip_stack
                )

                if conn_stack == IPStack.IPv4:
                    # IPv4 only
                    rtt_dnc = ["null:null:null:null:null"]
                    rtt_loss_dnc = ["null:null:null:null:null"]
                    rtt6_c = ["null:null:null:null:null"]
                    rtt6_loss_c = ["null:null:null:null:null"]
                    rtt_loss_c = ["0:0:0:0:0"]
                elif conn_stack is None:
                    # No connection
                    rtt_eq = "null:null:null:null:null"
                    rtt_loss_eq = "null:null:null:null:null"
                    rtt6_eq = "null:null:null:null:null"
                    rtt6_loss_eq = "null:null:null:null:null"
                elif conn_stack == IPStack.IPv6:
                    # IPv6 only
                    rtt_c = ["null:null:null:null:null"]
                    rtt_loss_c = ["null:null:null:null:null"]
                    rtt6_dnc = ["null:null:null:null:null"]
                    rtt6_loss_dnc = ["null:null:null:null:null"]
                    rtt6_loss_c = ["0:0:0:0:0"]
                elif conn_stack == IPStack.IPv4v6:
                    # IPv4 and IPv6
                    rtt_dnc = ["null:null:null:null:null"]
                    rtt_loss_dnc = ["null:null:null:null:null"]
                    rtt6_dnc = ["null:null:null:null:null"]
                    rtt6_loss_dnc = ["null:null:null:null:null"]
                    rtt_loss_c = ["0:0:0:0:0"]
                    rtt6_loss_c = ["0:0:0:0:0"]

                self.add_validator_list([
                    RttValidator(
                        exists=True,
                        members=[fingerprint],
                        does_not_contain=rtt_dnc,
                        contains=rtt_c,
                        equals=rtt_eq,
                    ),
                    RttLossValidator(
                        exists=True,
                        members=[fingerprint],
                        does_not_contain=rtt_loss_dnc,
                        contains=rtt_loss_c,
                        equals=rtt_loss_eq,
                    ),
                    Rtt6Validator(
                        exists=True,
                        members=[fingerprint],
                        does_not_contain=rtt6_dnc,
                        contains=rtt6_c,
                        equals=rtt6_eq,
                    ),
                    Rtt6LossValidator(
                        exists=True,
                        members=[fingerprint],
                        does_not_contain=rtt6_loss_dnc,
                        contains=rtt6_loss_c,
                        equals=rtt6_loss_eq,
                    ),
                ])

        return self

    def validate(self, value):
        for validator in self._validators:
            if not validator.validate(value):
                return False, (
                    "validator: " + type(validator).__name__ + ", event: " + str(value)
                )
        return True, ""

    def get_node_fingerprint(self):
        return self._node_fingerprint


class ConnectivityMatrixValidator(EventValidator):
    def __init__(
        self,
        exists=True,
        no_of_connections=0,
        all_connections_up=False,
        expected_states: Optional[List[int]] = None,
    ):
        super().__init__()
        self.add_validator(StringValidator(exists=exists))
        if exists:
            if no_of_connections != 0:
                self.add_validator(ConnectionCountValidator(count=no_of_connections))
            if all_connections_up or expected_states is not None:
                self.add_validator(
                    ConnectionStateValidator(
                        all_connections_up=all_connections_up,
                        expected_states=expected_states,
                    )
                )

    def validate(self, value):
        return super().validate(value.connectivity_matrix)


class ExternalLinksValidator(EventValidator):
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
        super().__init__()
        self.add_validator(
            StringValidator(
                exists=exists,
                equals=equals,
                contains=contains,
                does_not_contain=does_not_contain,
            )
        )
        if exists:
            if all_connections_up or expected_states is not None:
                self.add_validator(
                    ConnectionStateValidator(
                        all_connections_up=all_connections_up,
                        expected_states=expected_states,
                    )
                )
            if no_of_connections != 0:
                self.add_validator(ConnectionCountValidator(count=no_of_connections))

            self.add_validator(StringOccurrencesValidator(value="vpn", count=no_of_vpn))

    def validate(self, value):
        return super().validate(value.external_links)


class ConnectionMetricsValidator(Validator):
    def __init__(
        self,
        exists=True,
        members: Optional[List[str]] = None,
        equals="",
        contains: Optional[List[str]] = None,
        does_not_contain: Optional[List[str]] = None,
        attribute: str = "",
    ):
        self._members = members
        self._attribute = attribute
        self._validator = StringValidator(
            exists=exists,
            equals=equals,
            contains=contains,
            does_not_contain=does_not_contain,
        )

    # Add external peers to peers list
    #
    # External links can have two forms:
    #     - "vpn":md5(server_ip):<state>
    #     - <meshnet_id>:<node_fingerprint>:<state>
    # For convenience, vpn node is always identified by "vpn" string, other nodes by their fingerprint
    @staticmethod
    def process_external_peers(event, peers):
        if event.external_links != "":
            for link in event.external_links.split(","):
                parts = link.split(":")
                external_peer_fp = parts[0] if parts[0] == "vpn" else parts[1]
                peers.append(external_peer_fp)

    def validate(self, value):
        if not self._members:
            return self._validator.validate(getattr(value, self._attribute))

        value_list = getattr(value, self._attribute).split(",")
        peers = value.members.split(",")
        self.process_external_peers(value, peers)

        peers_values = dict(zip(peers, value_list))

        for member in self._members:
            value = peers_values.get(member)
            if value:
                assert self._validator.validate(value), (member, value)
            else:
                assert False, (
                    "validator: " + type(self).__name__ + ", member: " + str(member)
                )
        return True


class RttValidator(ConnectionMetricsValidator):
    def __init__(
        self,
        exists=True,
        members: Optional[List[str]] = None,
        equals="",
        contains: Optional[List[str]] = None,
        does_not_contain: Optional[List[str]] = None,
    ):
        super().__init__(
            exists, members, equals, contains, does_not_contain, attribute="rtt"
        )


class RttLossValidator(ConnectionMetricsValidator):
    def __init__(
        self,
        exists=True,
        members: Optional[List[str]] = None,
        equals="",
        contains: Optional[List[str]] = None,
        does_not_contain: Optional[List[str]] = None,
    ):
        super().__init__(
            exists, members, equals, contains, does_not_contain, attribute="rtt_loss"
        )


class Rtt6Validator(ConnectionMetricsValidator):
    def __init__(
        self,
        exists=True,
        members: Optional[List[str]] = None,
        equals="",
        contains: Optional[List[str]] = None,
        does_not_contain: Optional[List[str]] = None,
    ):
        super().__init__(
            exists, members, equals, contains, does_not_contain, attribute="rtt6"
        )


class Rtt6LossValidator(ConnectionMetricsValidator):
    def __init__(
        self,
        exists=True,
        members: Optional[List[str]] = None,
        equals="",
        contains: Optional[List[str]] = None,
        does_not_contain: Optional[List[str]] = None,
    ):
        super().__init__(
            exists, members, equals, contains, does_not_contain, attribute="rtt6_loss"
        )


class SentDataValidator(ConnectionMetricsValidator):
    def __init__(
        self,
        exists=True,
        members: Optional[List[str]] = None,
        equals="",
        contains: Optional[List[str]] = None,
        does_not_contain: Optional[List[str]] = None,
    ):
        super().__init__(
            exists, members, equals, contains, does_not_contain, attribute="sent_data"
        )


class ReceivedDataValidator(ConnectionMetricsValidator):
    def __init__(
        self,
        exists=True,
        members: Optional[List[str]] = None,
        equals="",
        contains: Optional[List[str]] = None,
        does_not_contain: Optional[List[str]] = None,
    ):
        super().__init__(
            exists,
            members,
            equals,
            contains,
            does_not_contain,
            attribute="received_data",
        )
