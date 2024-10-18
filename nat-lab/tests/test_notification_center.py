import json
import paho.mqtt.client as mqtt
import queue
import ssl
from config import CORE_API_CA_CERTIFICATE_PATH, MQTT_BROKER_IP, CORE_API_URL
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


def verify_mqtt_payload(payload):
    payload_json = json.loads(payload)

    verify_uuid(payload_json["message"]["data"]["metadata"]["message_id"])
    affected_machines_list = payload_json["message"]["data"]["event"]["attributes"][
        "affected_machines"
    ]
    for machine_uuid in affected_machines_list:
        verify_uuid(machine_uuid)


def run_mqtt_listener():
    payload_queue: queue.Queue[str] = queue.Queue(1)

    def on_message(_client, _userdata, message):
        payload_queue.put(f"{message.payload.decode()}")

    mqttc = mqtt.Client(client_id="reciever", protocol=mqtt.MQTTv311)

    mqttc.on_message = on_message

    mqttc.tls_set(certfile=None, keyfile=None, cert_reqs=ssl.CERT_NONE)
    mqttc.connect(MQTT_BROKER_IP, port=8883, keepalive=1)
    mqttc.subscribe("meshnet", qos=0)

    mqttc.loop_start()

    return payload_queue, mqttc


async def test_nc_register():
    async with AsyncExitStack() as exit_stack:
        # Setup connections
        connection_tag = ConnectionTag.DOCKER_CONE_CLIENT_1
        connection = await exit_stack.enter_async_context(
            new_connection_by_tag(connection_tag)
        )

        (mqtt_payload_queue, mqttc) = run_mqtt_listener()

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
        )
        response = MachineResponse(**https_process_stdout)

        identifier = response.identifier
        verify_uuid(identifier)

        assert request_json["public_key"] == response.public_key
        assert request_json["os"] == response.os
        assert request_json["os_version"] == response.os_version
        assert request_json["device_type"] == response.device_type
        assert response.traffic_routing_supported is False

        mqtt_payload = mqtt_payload_queue.get()
        verify_mqtt_payload(mqtt_payload)

        await send_https_request(
            connection,
            f"{machines_endpoint}/{identifier}",
            "DELETE",
            CORE_API_CA_CERTIFICATE_PATH,
            payload,
            expect_response=False,
        )

        machines = await send_https_request(
            connection,
            machines_endpoint,
            "GET",
            CORE_API_CA_CERTIFICATE_PATH,
        )

        assert len(machines) == 0

        mqtt_payload = mqtt_payload_queue.get()
        verify_mqtt_payload(mqtt_payload)

        # MQTT client cleanup
        mqttc.loop_stop()
