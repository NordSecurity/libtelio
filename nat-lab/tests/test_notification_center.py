import base64
import json
from asyncio import Event
from contextlib import AsyncExitStack
from dataclasses import dataclass
from tests.config import CORE_API_CA_CERTIFICATE_PATH, CORE_API_URL
from tests.helpers import send_https_request, verify_uuid
from tests.utils.connection import ConnectionTag
from tests.utils.connection_util import new_connection_by_tag
from tests.utils.logger import log
from tests.utils.output_notifier import OutputNotifier


@dataclass
class MachineResponse:
    identifier: str
    public_key: str
    hostname: str
    os: str
    os_version: str
    device_type: str
    nickname: str
    ip_addresses: list[str]
    discovery_key: str
    relay_address: str
    traffic_routing_supported: bool


CORE_API_CREDENTIALS = {
    "username": "token",
    "password": "48e9ef50178a68a716e38a9f9cd251e8be35e79a5c5f91464e92920425caa3d9",
}

BEARER_AUTHORIZATION_HEADER = (
    f"Bearer {CORE_API_CREDENTIALS['username']}:{CORE_API_CREDENTIALS['password']}"
)
BASIC_AUTHENTICATION_CREDENTIALS = (
    f"{CORE_API_CREDENTIALS['username']}:{CORE_API_CREDENTIALS['password']}"
)
BASIC_CREDENTIALS_BYTES = BASIC_AUTHENTICATION_CREDENTIALS.encode("utf-8")
BASIC_AUTHORIZATION_HEADER = (
    f"Basic {base64.b64encode(BASIC_CREDENTIALS_BYTES).decode('utf-8')}"
)


def verify_mqtt_payload(payload):
    payload_json = json.loads(payload)

    verify_uuid(payload_json["message"]["data"]["metadata"]["message_id"])
    affected_machines_list = payload_json["message"]["data"]["event"]["attributes"][
        "affected_machines"
    ]
    for machine_uuid in affected_machines_list:
        verify_uuid(machine_uuid)


async def run_mqtt_listener(
    exit_stack,
    connection,
    mqtt_broker_host,
    mqtt_broker_port,
    mqtt_broker_user,
    mqtt_broker_password,
    output_notifier,
):
    stdout_buffer = []

    async def stdout_stderr_callback(output):
        log.info("MQTT Listener output: %s", output)
        stdout_buffer.append(output)
        await output_notifier.handle_output(output)

    mqtt_process = await exit_stack.enter_async_context(
        connection.create_process([
            "python3",
            "-u",
            "/opt/bin/mqtt-listener.py",
            mqtt_broker_host,
            mqtt_broker_port,
            mqtt_broker_user,
            mqtt_broker_password,
        ]).run(
            stdout_callback=stdout_stderr_callback,
            stderr_callback=stdout_stderr_callback,
        )
    )

    try:
        await mqtt_process.wait_stdin_ready(timeout=10.0)
        log.info("MQTT listener process stdin is ready")
    except TimeoutError as e:
        raise TimeoutError(
            f"Timed out waiting for MQTT listener stdin readiness: {e}"
        ) from e

    return stdout_buffer


async def get_mqtt_broker_credentials(connection):
    endpoint = f"{CORE_API_URL}/v1/notifications/tokens"
    json_data = {
        "user_hash": "user-hash",
        "app_user_uid": "app-user-uid",
        "platform_id": 1,
        "protocol": "tcp",
    }
    payload = json.dumps(json_data)
    response = await send_https_request(
        connection,
        endpoint,
        "POST",
        CORE_API_CA_CERTIFICATE_PATH,
        payload,
        authorization_header=BASIC_AUTHORIZATION_HEADER,
    )
    _, host, port = response["endpoint"].replace("//", "").split(":")
    user, password = response["username"], response["password"]
    return host, port, user, password


def create_output_notifier(events):
    output_notifier = OutputNotifier()
    event_objects = {event: Event() for event in events}
    for event, event_obj in event_objects.items():
        output_notifier.notify_output(event, event_obj)
    return output_notifier, event_objects


async def test_nc_register():
    async with AsyncExitStack() as exit_stack:
        # Setup connections
        connection_tag = ConnectionTag.DOCKER_CONE_CLIENT_1
        connection = await exit_stack.enter_async_context(
            new_connection_by_tag(connection_tag)
        )

        mqtt_connection = await exit_stack.enter_async_context(
            new_connection_by_tag(ConnectionTag.DOCKER_CONE_CLIENT_2)
        )
        mqtt_host, mqtt_port, user, password = await get_mqtt_broker_credentials(
            connection
        )

        # Clean up any pre-existing machines before running the test
        machines_endpoint = f"{CORE_API_URL}/v1/meshnet/machines"
        existing_machines = await send_https_request(
            connection,
            machines_endpoint,
            "GET",
            CORE_API_CA_CERTIFICATE_PATH,
            authorization_header=BEARER_AUTHORIZATION_HEADER,
        )
        if existing_machines:
            for machine in existing_machines:
                await send_https_request(
                    connection,
                    f"{machines_endpoint}/{machine['identifier']}",
                    "DELETE",
                    CORE_API_CA_CERTIFICATE_PATH,
                    expect_response=False,
                    authorization_header=BEARER_AUTHORIZATION_HEADER,
                )

        output_notifier, events = create_output_notifier(
            ["Connected to MQTT Broker", "message"]
        )
        connected_event = events["Connected to MQTT Broker"]
        message_event = events["message"]

        stdout_buffer = await run_mqtt_listener(
            exit_stack,
            mqtt_connection,
            mqtt_host,
            mqtt_port,
            user,
            password,
            output_notifier,
        )

        await connected_event.wait()

        # Register machine - this is a minimal version which should be also supported
        request_json = {
            "public_key": "some-public-key",
            "hardware_identifier": "HWID12345",
            "os": "Linux",
            "os_version": "5.10",
            "device_type": "router",
        }
        machines_endpoint = f"{CORE_API_URL}/v1/meshnet/machines"
        payload = json.dumps(request_json, separators=(",", ":"))

        https_process_stdout = await send_https_request(
            connection,
            machines_endpoint,
            "POST",
            CORE_API_CA_CERTIFICATE_PATH,
            payload,
            authorization_header=BEARER_AUTHORIZATION_HEADER,
        )
        response = MachineResponse(**https_process_stdout)

        identifier = response.identifier
        verify_uuid(identifier)

        assert request_json["public_key"] == response.public_key
        assert request_json["os"] == response.os
        assert request_json["os_version"] == response.os_version
        assert request_json["device_type"] == response.device_type
        assert response.traffic_routing_supported is False

        await message_event.wait()

        mqtt_payload = stdout_buffer[
            -1
        ]  # The last item in the buffer is expected to be a message from the meshnet topic
        assert mqtt_payload
        verify_mqtt_payload(mqtt_payload)

        output_notifier, events = create_output_notifier(
            ["Connected to MQTT Broker", "message"]
        )
        connected_event = events["Connected to MQTT Broker"]
        message_event = events["message"]

        stdout_buffer = await run_mqtt_listener(
            exit_stack,
            mqtt_connection,
            mqtt_host,
            mqtt_port,
            user,
            password,
            output_notifier,
        )
        await connected_event.wait()

        await send_https_request(
            connection,
            f"{machines_endpoint}/{identifier}",
            "DELETE",
            CORE_API_CA_CERTIFICATE_PATH,
            payload,
            expect_response=False,
            authorization_header=BEARER_AUTHORIZATION_HEADER,
        )

        machines = await send_https_request(
            connection,
            machines_endpoint,
            "GET",
            CORE_API_CA_CERTIFICATE_PATH,
            authorization_header=BEARER_AUTHORIZATION_HEADER,
        )

        assert machines is not None
        assert len(machines) == 0

        await message_event.wait()

        mqtt_payload = stdout_buffer[
            -1
        ]  # The last item in the buffer is expected to be a message from the meshnet topic
        assert mqtt_payload
        verify_mqtt_payload(mqtt_payload)
