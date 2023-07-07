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
        else:
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
    def __init__(self, all_connections_up, expected_state):
        self._all_connections_up = all_connections_up
        self._expected_state = expected_state

    def validate(self, value):
        # Each connection is separated by a ',':
        # [########connection1#########, ########connection2#########]
        connections = value.split(",")
        # It consists in three info-values separated each by ':' and
        # the connection_state will always be the last one:
        # [info1:info2:connection_state, info1:info2:connection_state]
        if self._all_connections_up:
            return not any(conn.split(":")[2] == "0" for conn in connections)
        elif self._expected_state != "":
            return all(
                conn.split(":")[2] == self._expected_state for conn in connections
            )


class StringValidator:
    def __init__(self, exists=True, equals="", contains=[], does_not_contain=[]):
        self._validators = []

        if exists:
            self._validators.append(ExistanceValidator())
        else:
            self._validators.append(InexistanceValidator())
            return

        if equals != "":
            self._validators.append(StringEqualsValidator(value=equals))

        for substring in contains:
            self._validators.append(
                StringContainmentValidator(value=substring, contains=True)
            )

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
        contains=[],
        does_not_contain=[],
        all_connections_up=False,
        no_of_connections=0,
        no_of_vpn=0,
    ):
        self._validators = [
            StringValidator(
                exists=exists,
                equals=equals,
                contains=contains,
                does_not_contain=does_not_contain,
            )
        ]

        if exists:
            if all_connections_up:
                self._validators.append(
                    ConnectionStateValidator(
                        all_connections_up=all_connections_up, expected_state=""
                    )  # type: ignore
                )
            if no_of_connections != 0:
                self._validators.append(
                    ConnectionCountValidator(count=no_of_connections)  # type: ignore
                )

            self._validators.append(
                StringOccurrencesValidator(value="vpn", count=no_of_vpn)  # type: ignore
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
        expected_state="",
    ):
        self._validators = [StringValidator(exists=exists)]
        if exists:
            if no_of_connections != 0:
                self._validators.append(
                    ConnectionCountValidator(count=no_of_connections)  # type: ignore
                )
            if all_connections_up or expected_state != "":
                self._validators.append(
                    ConnectionStateValidator(
                        all_connections_up=all_connections_up,
                        expected_state=expected_state,
                    )  # type: ignore
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
    def __init__(self, exists=True, equals="", contains=[], does_not_contain=[]):
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


class ReceivedDataValidator:
    def __init__(self, exists=True):
        self._validator = StringValidator(exists=exists)

    def validate(self, event):
        return self._validator.validate(event.received_data)


class RttValidator:
    def __init__(self, exists=True):
        self._validator = StringValidator(exists=exists)

    def validate(self, event):
        return self._validator.validate(event.rtt)


class SentDataValidator:
    def __init__(self, exists=True):
        self._validator = StringValidator(exists=exists)

    def validate(self, event):
        return self._validator.validate(event.sent_data)


class EventValidator:
    def __init__(self):
        self._validators = []

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
        contains=[],
        does_not_contain=[],
        all_connections_up=False,
        no_of_connections=0,
        no_of_vpn=0,
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
            )
        )
        return self

    def add_connectivity_matrix_validator(
        self,
        exists=True,
        no_of_connections=0,
        all_connections_up=False,
        expected_state="",
    ):
        self._validators.append(
            ConnectivityMatrixValidator(
                exists,
                no_of_connections=no_of_connections,
                all_connections_up=all_connections_up,
                expected_state=expected_state,
            )
        )
        return self

    def add_fingerprint_validator(self, exists=True, equals=""):
        self._validators.append(FingerprintValidator(exists=exists, equals=equals))
        return self

    def add_members_validator(
        self, exists=True, equals="", contains=[], does_not_contain=[]
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

    def add_received_data_validator(self, exists=True):
        self._validators.append(ReceivedDataValidator(exists=exists))
        return self

    def add_rtt_validator(self, exists=True):
        self._validators.append(RttValidator(exists=exists))
        return self

    def add_sent_data_validator(self, exists=True):
        self._validators.append(SentDataValidator(exists=exists))
        return self

    def validate(self, event) -> bool:
        for validator in self._validators:
            if not validator.validate(event):
                return False
        return True


def basic_validator(
    node_fingerprint: str = "", heartbeat_interval: int = 3600, meshnet_id: str = ""
) -> EventValidator:
    event_validator = (
        EventValidator()
        .add_name_validator("heartbeat")
        .add_category_validator("service_quality")
        .add_fingerprint_validator(exists=True, equals=meshnet_id)
        .add_heartbeat_interval_validator(value=heartbeat_interval, equals=True)
        .add_connection_duration_validator(exists=True)
        .add_received_data_validator(exists=True)
        .add_rtt_validator(exists=True)
        .add_sent_data_validator(exists=True)
    )
    if node_fingerprint != "":
        # Current node should always be in the members list
        event_validator.add_members_validator(exists=True, contains=[node_fingerprint])

    return event_validator
