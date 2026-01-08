from tests.utils import analytics
from tests.utils.testing import log_test_passed

TEST_EVENT = analytics.Event(
    name="heartbeat",
    category="service_quality",
    datetime_local="2023-08-10T15:03:25.605768807+00:00",
    external_links="86c4375d-014b:delta:15,edcd3eea-7aca:charlie:15",
    connectivity_matrix="1:2:7,0:2:11,0:1:15",
    fp="86bee206-9082",
    members="gamma, beta",
    connection_duration="0;11;11",
    heartbeat_interval=3600,
    received_data="0:0:0:0:0",
    rtt="0:0:0:0:0",
    rtt_loss="0:0:0:0:0",
    rtt6="0:0:0:0:0",
    rtt6_loss="0:0:0:0:0",
    sent_data="0:0:0:0:0",
    nat_traversal_conn_info="1:2:120:49:2000:4000",
    derp_conn_info="e086aa137fa19f67d27b39d0eca18610:120:257:101",
)

DUMMY_EVENT = analytics.Event(
    name="heartbeet",
    category="service_qwuality",
    datetime_local="2026-08-10T15:03:25.605768807+00:00",
    external_links="86c4375d-014b:delta:0",
    connectivity_matrix="1:2:3,0:2:2",
    fp="86bee206-9083",
    members="gamma",
    connection_duration="",
    heartbeat_interval=360,
    received_data="",
    rtt="",
    rtt_loss="",
    rtt6="",
    rtt6_loss="",
    sent_data="",
    nat_traversal_conn_info="",
    derp_conn_info="",
)


def check_validator(validator, true_event, false_event) -> None:
    res = validator.validate(true_event)
    assert res[0] if issubclass(type(validator), analytics.EventValidator) else res
    res = validator.validate(false_event)
    assert not (
        res[0] if issubclass(type(validator), analytics.EventValidator) else res
    )


def test_existance_validator() -> None:
    check_validator(analytics.ExistanceValidator(), "test", "")

    log_test_passed()


def test_inexistance_validator() -> None:
    check_validator(analytics.InexistanceValidator(), "", "test")

    log_test_passed()


def test_string_equals_validator() -> None:
    check_validator(analytics.StringEqualsValidator("test"), "test", "apple")

    log_test_passed()


def test_string_containment_validator() -> None:
    check_validator(
        analytics.StringContainmentValidator("test"), "truetestapple", "trueapple"
    )

    log_test_passed()


def test_string_occurences_validator() -> None:
    check_validator(
        analytics.StringOccurrencesValidator(count=2, value="true"),
        "testtrueappletrue",
        "testappletrue",
    )

    log_test_passed()


def test_integer_equals_validator() -> None:
    check_validator(analytics.IntegerEqualityValidator(7), 7, 5)

    log_test_passed()


def test_integer_not_equals_validator() -> None:
    check_validator(analytics.IntegerEqualityValidator(5, False), 7, 5)

    log_test_passed()


def test_connection_count_validator() -> None:
    check_validator(analytics.ConnectionCountValidator(2), "gamma, beta", "beta")

    log_test_passed()


def test_connection_state_validator() -> None:
    check_validator(
        analytics.ConnectionStateValidator(
            expected_states=[
                (
                    analytics.DERP_BIT
                    | analytics.WG_BIT
                    | analytics.IPV4_BIT
                    | analytics.IPV6_BIT
                ),
                (
                    analytics.DERP_BIT
                    | analytics.WG_BIT
                    | analytics.IPV4_BIT
                    | analytics.IPV6_BIT
                ),
            ],
            all_connections_up=False,
        ),
        TEST_EVENT.external_links,
        DUMMY_EVENT.external_links,
    )
    check_validator(
        analytics.ConnectionStateValidator(
            all_connections_up=True,
        ),
        TEST_EVENT.external_links,
        DUMMY_EVENT.external_links,
    )

    log_test_passed()


def test_string_validator() -> None:
    check_validator(
        analytics.StringValidator(
            exists=True,
            equals="truetest",
            contains=["test"],
            does_not_contain=["apple"],
        ),
        "truetest",
        "appletest",
    )

    log_test_passed()


def test_name_validator() -> None:
    check_validator(analytics.NameValidator("heartbeat"), TEST_EVENT, DUMMY_EVENT)

    log_test_passed()


def test_category_validator() -> None:
    check_validator(
        analytics.CategoryValidator("service_quality"), TEST_EVENT, DUMMY_EVENT
    )

    log_test_passed()


def test_external_links_validator() -> None:
    check_validator(
        analytics.ExternalLinksValidator(
            exists=True,
            contains=["delta", "charlie"],
            does_not_contain=["alpha"],
            all_connections_up=False,
            no_of_connections=2,
            expected_states=[
                (
                    analytics.DERP_BIT
                    | analytics.WG_BIT
                    | analytics.IPV4_BIT
                    | analytics.IPV6_BIT
                ),
                (
                    analytics.DERP_BIT
                    | analytics.WG_BIT
                    | analytics.IPV4_BIT
                    | analytics.IPV6_BIT
                ),
            ],
        ),
        TEST_EVENT,
        DUMMY_EVENT,
    )
    check_validator(
        analytics.ExternalLinksValidator(
            exists=True,
            contains=["delta", "charlie"],
            does_not_contain=["alpha"],
            all_connections_up=True,
            no_of_connections=2,
        ),
        TEST_EVENT,
        DUMMY_EVENT,
    )

    log_test_passed()


def test_connectivity_matrix_validator() -> None:
    check_validator(
        analytics.ConnectivityMatrixValidator(
            exists=True, no_of_connections=3, all_connections_up=True
        ),
        TEST_EVENT,
        DUMMY_EVENT,
    )
    check_validator(
        analytics.ConnectivityMatrixValidator(
            exists=True,
            no_of_connections=3,
            all_connections_up=False,
            expected_states=[
                (analytics.DERP_BIT | analytics.WG_BIT | analytics.IPV4_BIT),
                (analytics.DERP_BIT | analytics.WG_BIT | analytics.IPV6_BIT),
                (
                    analytics.DERP_BIT
                    | analytics.WG_BIT
                    | analytics.IPV4_BIT
                    | analytics.IPV6_BIT
                ),
            ],
        ),
        TEST_EVENT,
        DUMMY_EVENT,
    )

    log_test_passed()


def test_fingerprint_validator() -> None:
    check_validator(
        analytics.FingerprintValidator(equals="86bee206-9082"), TEST_EVENT, DUMMY_EVENT
    )

    log_test_passed()


def test_members_validator() -> None:
    check_validator(
        analytics.MembersValidator(
            exists=True,
            contains=["gamma", "beta"],
            does_not_contain=["alpha"],
        ),
        TEST_EVENT,
        DUMMY_EVENT,
    )

    log_test_passed()


def test_connection_duration_validator() -> None:
    check_validator(analytics.ConnectionDurationValidator(), TEST_EVENT, DUMMY_EVENT)

    log_test_passed()


def test_heartbeat_interval_validator() -> None:
    check_validator(analytics.HeartbeatIntervalValidator(3600), TEST_EVENT, DUMMY_EVENT)

    log_test_passed()


def test_recieved_data_validator() -> None:
    check_validator(analytics.ReceivedDataValidator(), TEST_EVENT, DUMMY_EVENT)

    log_test_passed()


def test_rtt_validator() -> None:
    check_validator(analytics.RttValidator(), TEST_EVENT, DUMMY_EVENT)

    log_test_passed()


def test_rtt_loss_validator() -> None:
    check_validator(analytics.RttLossValidator(), TEST_EVENT, DUMMY_EVENT)

    log_test_passed()


def test_rtt6_validator() -> None:
    check_validator(analytics.Rtt6Validator(), TEST_EVENT, DUMMY_EVENT)

    log_test_passed()


def test_rtt6_loss_validator() -> None:
    check_validator(analytics.Rtt6LossValidator(), TEST_EVENT, DUMMY_EVENT)

    log_test_passed()


def test_sent_data_validator() -> None:
    check_validator(analytics.SentDataValidator(), TEST_EVENT, DUMMY_EVENT)

    log_test_passed()


def test_nat_traversal_conn_info() -> None:
    check_validator(
        analytics.NatTraversalConnInfoValidator(
            "aaaa", "bbbb", False, equals="1:2:120:49:2000:4000"
        ),
        TEST_EVENT,
        DUMMY_EVENT,
    )

    log_test_passed()


def test_derp_conn_info() -> None:
    check_validator(analytics.DerpConnInfoValidator(), TEST_EVENT, DUMMY_EVENT)

    log_test_passed()


def test_lana_event_validator() -> None:
    test_validator = analytics.EventValidator.new_with_basic_validators(
        "beta", meshnet_id="86bee206-9082"
    ).add_validator_list([
        analytics.ConnectivityMatrixValidator(
            exists=True,
            no_of_connections=3,
            all_connections_up=True,
        ),
        analytics.MembersValidator(
            exists=True,
            contains=["gamma", "beta"],
            does_not_contain=["alpha"],
        ),
        analytics.ExternalLinksValidator(
            exists=True,
            contains=["delta", "charlie"],
            does_not_contain=["alpha", "beta", "gamma"],
            all_connections_up=True,
            no_of_connections=2,
        ),
    ])
    res = test_validator.validate(TEST_EVENT)
    assert res[0], res[1]
    res = test_validator.validate(DUMMY_EVENT)
    assert not res[0], res[1]

    log_test_passed()
