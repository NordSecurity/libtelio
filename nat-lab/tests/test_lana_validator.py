from utils.analytics import *

test_event = Event(
    name="heartbeat",
    category="service_quality",
    datetime_local="2023-08-10T15:03:25.605768807+00:00",
    external_links="86c4375d-014b:gamma:3,edcd3eea-7aca:beta:3",
    connectivity_matrix="'1:2:3,0:2:2,0:1:3'",
    fp="86bee206-9082",
    members="gamma, beta",
    connection_duration="0;11;11",
    heartbeat_interval=3600,
    received_data="0:0:0:0:0",
    rtt="0:0:0:0:0",
    sent_data="0:0:0:0:0",
    nat_type="PortRestrictedCone",
    mem_nat_types="Symmetric,PortRestrictedCone",
)


def test_lana_validators() -> None:

    test_validator = (
        basic_validator(meshnet_id="86bee206-9082")
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
            contains=["gamma", "beta"],
            does_not_contain=["alpha"],
            all_connections_up=True,
            no_of_connections=2,
        )
    )

    assert test_validator.validate(test_event)
