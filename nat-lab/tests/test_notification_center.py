import base64
import json
from asyncio import sleep
from config import CORE_API_CA_CERTIFICATE_PATH, CORE_API_URL
from contextlib import AsyncExitStack
from dataclasses import dataclass
from helpers import send_https_request, verify_uuid
from utils.connection_util import ConnectionTag, new_connection_by_tag


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
):
    mqtt_process = await exit_stack.enter_async_context(
        connection.create_process([
            "python3",
            "/opt/bin/mqtt-listener.py",
            mqtt_broker_host,
            mqtt_broker_port,
            mqtt_broker_user,
            mqtt_broker_password,
        ]).run()
    )
    while not mqtt_process.is_executing():
        await sleep(0.1)
    return mqtt_process


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
        mqtt_process = await run_mqtt_listener(
            exit_stack, mqtt_connection, mqtt_host, mqtt_port, user, password
        )

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

        mqtt_payload = mqtt_process.get_stdout()
        while "message_id" not in mqtt_payload:
            await sleep(0.1)
            mqtt_payload = mqtt_process.get_stdout()

        assert mqtt_payload
        verify_mqtt_payload(mqtt_payload)

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

        assert len(machines) == 0

        mqtt_payload = mqtt_process.get_stdout()
        while "message_id" not in mqtt_payload:
            await sleep(0.1)
            mqtt_payload = mqtt_process.get_stdout()
        assert mqtt_payload
        verify_mqtt_payload(mqtt_payload)
