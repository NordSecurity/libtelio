import json
from asyncio import sleep
from contextlib import AsyncExitStack
from dataclasses import dataclass
from utils.connection_util import ConnectionTag, new_connection_by_tag
from uuid import UUID


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


def verify_uuid(uuid_to_test, version=4):
    try:
        uuid_obj = UUID(uuid_to_test, version=version)
    except ValueError:
        assert False, "Not a valid UUID"
    assert str(uuid_obj) == uuid_to_test, "Not a valid UUID"


def verify_mqtt_payload(payload):
    payload_json = json.loads(payload)

    verify_uuid(payload_json["message"]["data"]["metadata"]["message_id"])
    affected_machines_list = payload_json["message"]["data"]["event"]["attributes"][
        "affected_machines"
    ]
    for machine_uuid in affected_machines_list:
        verify_uuid(machine_uuid)


async def run_mqtt_listener(exit_stack, connection):
    # Start listening for mqtt message
    mqtt_process = await exit_stack.enter_async_context(
        connection.create_process(["python3", "/opt/bin/mqtt_listener.py"]).run()
    )

    # Allows mqtt process to run
    await sleep(0.1)

    return mqtt_process


async def test_nc_register():
    async with AsyncExitStack() as exit_stack:
        # Setup connections
        connection_alpha = await exit_stack.enter_async_context(
            new_connection_by_tag(ConnectionTag.DOCKER_CONE_CLIENT_1)
        )
        connection_beta = await exit_stack.enter_async_context(
            new_connection_by_tag(ConnectionTag.DOCKER_CONE_CLIENT_2)
        )

        mqtt_process = await run_mqtt_listener(exit_stack, connection_alpha)

        # Register machine - this is a minimal version which should be also supported
        request_json = {
            "public_key": "some-public-key",
            "hardware_identifier": "HWID12345",
            "os": "Linux",
            "os_version": "5.10",
            "device_type": "router",
        }
        payload = json.dumps(request_json, separators=(",", ":"))
        http_process = await connection_beta.create_process([
            "curl",
            "-X",
            "POST",
            "http://10.0.80.86:8080/v1/meshnet/machines",
            "-H",
            '"Content-Type: application/json"',
            "-d",
            f"{payload}",
        ]).execute()

        json_obj = json.loads(http_process.get_stdout())
        response = MachineResponse(**json_obj)

        identifier = response.identifier
        verify_uuid(identifier)

        assert request_json["public_key"] == response.public_key
        assert request_json["os"] == response.os
        assert request_json["os_version"] == response.os_version
        assert request_json["device_type"] == response.device_type
        assert response.traffic_routing_supported is False

        # With 1 second keepalive it should get the message after this sleep
        await sleep(2)

        verify_mqtt_payload(mqtt_process.get_stdout())

        mqtt_process = await run_mqtt_listener(exit_stack, connection_alpha)

        http_process = await connection_beta.create_process([
            "curl",
            "-i",
            "-X",
            "DELETE",
            f"http://10.0.80.86:8080/v1/meshnet/machines/{identifier}",
        ]).execute()

        status = http_process.get_stdout().split(" ")[1]
        assert status == "204"

        # With 1 second keepalive it should get the message after this sleep
        await sleep(2)

        verify_mqtt_payload(mqtt_process.get_stdout())
