import sqlite3
import json
from dataclasses import dataclass, field
from dataclasses_json import dataclass_json, Undefined
from dataclasses_json import config as json_config
from flatten_json import flatten  # type: ignore

DEFAULT_TABLE_NAME = "queue_elements"


@dataclass_json(undefined=Undefined.EXCLUDE)
@dataclass
class Event:
    name: str = field(metadata=json_config(field_name="event_name"))
    category: str = field(metadata=json_config(field_name="event_category"))
    datetime_local: str = field(metadata=json_config(field_name="event_datetime_local"))
    external_links: str = field(
        metadata=json_config(
            field_name="context_application_config_current_state_external_links"
        )
    )
    connectivity_matrix: str = field(
        metadata=json_config(
            field_name="context_application_config_current_state_internal_meshnet_connectivity_matrix"
        )
    )
    fp: str = field(
        metadata=json_config(
            field_name="context_application_config_current_state_internal_meshnet_fp"
        )
    )
    members: str = field(
        metadata=json_config(
            field_name="context_application_config_current_state_internal_meshnet_members"
        )
    )
    connection_duration: str = field(
        metadata=json_config(field_name="body_connection_duration")
    )
    heartbeat_interval: int = field(
        metadata=json_config(field_name="body_heartbeat_interval")
    )
    received_data: str = field(metadata=json_config(field_name="body_received_data"))
    rtt: str = field(metadata=json_config(field_name="body_rtt"))
    sent_data: str = field(metadata=json_config(field_name="body_sent_data"))


def fetch_moose_events(database_name):
    database_connection = sqlite3.connect(database_name)
    database_cursor = database_connection.cursor()

    event_list = []
    try:
        database_cursor.execute("SELECT * FROM " + DEFAULT_TABLE_NAME)
        events = database_cursor.fetchall()

        for event in events:
            event_json = json.loads(event[0])
            flatten_event_json = flatten(event_json)
            flatten_json_str = json.dumps(flatten_event_json).replace("'", '"')
            event_list.append(Event.from_json(flatten_json_str))
    except sqlite3.OperationalError:
        print("No such table: " + DEFAULT_TABLE_NAME)

    return event_list
