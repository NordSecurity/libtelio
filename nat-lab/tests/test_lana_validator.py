import utils.analytics as Validator

TEST_EVENT = Validator.Event(
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
    nat_type="PortRestrictedCone",
    mem_nat_types="Symmetric,PortRestrictedCone",
)

DUMMY_EVENT = Validator.Event(
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
    nat_type="Symmetric",
    mem_nat_types="PortRestrictedCone,PortRestrictedCone",
)


def check_validator(validator, true_event, false_event) -> None:
    assert validator.validate(true_event)
    assert not validator.validate(false_event)


def test_existance_validator() -> None:
    check_validator(Validator.ExistanceValidator(), "test", "")


def test_inexistance_validator() -> None:
    check_validator(Validator.InexistanceValidator(), "", "test")


def test_string_equals_validator() -> None:
    check_validator(Validator.StringEqualsValidator("test"), "test", "apple")


def test_string_containment_validator() -> None:
    check_validator(
        Validator.StringContainmentValidator("test"), "truetestapple", "trueapple"
    )


def test_string_occurences_validator() -> None:
    check_validator(
        Validator.StringOccurrencesValidator(count=2, value="true"),
        "testtrueappletrue",
        "testappletrue",
    )


def test_integer_equals_validator() -> None:
    check_validator(Validator.IntegerEqualsValidator(7), 7, 5)


def test_integer_not_equals_validator() -> None:
    check_validator(Validator.IntegerNotEqualsValidator(5), 7, 5)


def test_connection_count_validator() -> None:
    check_validator(Validator.ConnectionCountValidator(2), "gamma, beta", "beta")


def test_connection_state_validator() -> None:
    check_validator(
        Validator.ConnectionStateValidator(
            expected_states=[
                (
                    Validator.DERP_BIT
                    | Validator.WG_BIT
                    | Validator.IPV4_BIT
                    | Validator.IPV6_BIT
                ),
                (
                    Validator.DERP_BIT
                    | Validator.WG_BIT
                    | Validator.IPV4_BIT
                    | Validator.IPV6_BIT
                ),
            ],
            all_connections_up=False,
        ),
        TEST_EVENT.external_links,
        DUMMY_EVENT.external_links,
    )
    check_validator(
        Validator.ConnectionStateValidator(
            all_connections_up=True,
        ),
        TEST_EVENT.external_links,
        DUMMY_EVENT.external_links,
    )


def test_string_validator() -> None:
    check_validator(
        Validator.StringValidator(
            exists=True,
            equals="truetest",
            contains=["test"],
            does_not_contain=["apple"],
        ),
        "truetest",
        "appletest",
    )


def test_name_validator() -> None:
    check_validator(Validator.NameValidator("heartbeat"), TEST_EVENT, DUMMY_EVENT)


def test_category_validator() -> None:
    check_validator(
        Validator.CategoryValidator("service_quality"), TEST_EVENT, DUMMY_EVENT
    )


def test_external_links_validator() -> None:
    check_validator(
        Validator.ExternalLinksValidator(
            exists=True,
            contains=["delta", "charlie"],
            does_not_contain=["alpha"],
            all_connections_up=False,
            no_of_connections=2,
            expected_states=[
                (
                    Validator.DERP_BIT
                    | Validator.WG_BIT
                    | Validator.IPV4_BIT
                    | Validator.IPV6_BIT
                ),
                (
                    Validator.DERP_BIT
                    | Validator.WG_BIT
                    | Validator.IPV4_BIT
                    | Validator.IPV6_BIT
                ),
            ],
        ),
        TEST_EVENT,
        DUMMY_EVENT,
    )
    check_validator(
        Validator.ExternalLinksValidator(
            exists=True,
            contains=["delta", "charlie"],
            does_not_contain=["alpha"],
            all_connections_up=True,
            no_of_connections=2,
        ),
        TEST_EVENT,
        DUMMY_EVENT,
    )


def test_connectivity_matrix_validator() -> None:
    check_validator(
        Validator.ConnectivityMatrixValidator(
            exists=True, no_of_connections=3, all_connections_up=True
        ),
        TEST_EVENT,
        DUMMY_EVENT,
    )
    check_validator(
        Validator.ConnectivityMatrixValidator(
            exists=True,
            no_of_connections=3,
            all_connections_up=False,
            expected_states=[
                (Validator.DERP_BIT | Validator.WG_BIT | Validator.IPV4_BIT),
                (Validator.DERP_BIT | Validator.WG_BIT | Validator.IPV6_BIT),
                (
                    Validator.DERP_BIT
                    | Validator.WG_BIT
                    | Validator.IPV4_BIT
                    | Validator.IPV6_BIT
                ),
            ],
        ),
        TEST_EVENT,
        DUMMY_EVENT,
    )


def test_fingerprint_validator() -> None:
    check_validator(
        Validator.FingerprintValidator(equals="86bee206-9082"), TEST_EVENT, DUMMY_EVENT
    )


def test_members_validator() -> None:
    check_validator(
        Validator.MembersValidator(
            exists=True,
            contains=["gamma", "beta"],
            does_not_contain=["alpha"],
        ),
        TEST_EVENT,
        DUMMY_EVENT,
    )


def test_connection_duration_validator() -> None:
    check_validator(Validator.ConnectionDurationValidator(), TEST_EVENT, DUMMY_EVENT)


def test_heartbeat_interval_validator() -> None:
    check_validator(Validator.HeartbeatIntervalValidator(3600), TEST_EVENT, DUMMY_EVENT)


def test_recieved_data_validator() -> None:
    check_validator(Validator.ReceivedDataValidator(), TEST_EVENT, DUMMY_EVENT)


def test_rtt_validator() -> None:
    check_validator(Validator.RttValidator(), TEST_EVENT, DUMMY_EVENT)


def test_rtt_loss_validator() -> None:
    check_validator(Validator.RttLossValidator(), TEST_EVENT, DUMMY_EVENT)


def test_rtt6_validator() -> None:
    check_validator(Validator.Rtt6Validator(), TEST_EVENT, DUMMY_EVENT)


def test_rtt6_loss_validator() -> None:
    check_validator(Validator.Rtt6LossValidator(), TEST_EVENT, DUMMY_EVENT)


def test_sent_data_validator() -> None:
    check_validator(Validator.SentDataValidator(), TEST_EVENT, DUMMY_EVENT)


def test_nat_type_validator() -> None:
    check_validator(
        Validator.NatTypeValidator("PortRestrictedCone"), TEST_EVENT, DUMMY_EVENT
    )


def test_nat_traversal_conn_info() -> None:
    check_validator(Validator.NatTraversalConnInfoValidator(), TEST_EVENT, DUMMY_EVENT)


def test_derp_conn_info() -> None:
    check_validator(Validator.DerpConnInfoValidator(), TEST_EVENT, DUMMY_EVENT)


def test_mem_nat_type_validator() -> None:
    check_validator(
        Validator.MemNatTypeValidator(["Symmetric", "PortRestrictedCone"]),
        TEST_EVENT,
        DUMMY_EVENT,
    )


def test_lana_event_validator() -> None:
    test_validator = (
        Validator.basic_validator("beta", meshnet_id="86bee206-9082")
        .add_connectivity_matrix_validator(
            exists=True,
            no_of_connections=3,
            all_connections_up=True,
        )
        .add_members_validator(
            exists=True,
            contains=["gamma", "beta"],
            does_not_contain=["alpha"],
        )
        .add_nat_type_validators(
            is_nat_type_collection_enabled=True,
            nat_type="PortRestrictedCone",
            nat_mem=["Symmetric", "PortRestrictedCone"],
        )
        .add_external_links_validator(
            exists=True,
            contains=["delta", "charlie"],
            does_not_contain=["alpha", "beta", "gamma"],
            all_connections_up=True,
            no_of_connections=2,
        )
    )
    res = test_validator.validate(TEST_EVENT)
    assert res[0], res[1]
    res = test_validator.validate(DUMMY_EVENT)
    assert not res[0], res[1]
