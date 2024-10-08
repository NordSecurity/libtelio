#!/usr/bin/python3

import json
import paho.mqtt.client as mqtt  # type: ignore # pylint: disable=import-error
from dataclasses import asdict, dataclass
from http.server import BaseHTTPRequestHandler, HTTPServer
from itertools import count
from pprint import pprint
from typing import Optional
from uuid import uuid4


@dataclass
class MachineCreateRequest:
    public_key: str
    hardware_identifier: str
    os: str
    os_version: str
    device_type: str = "other"
    app_user_uid: Optional[str] = None
    nickname: Optional[str] = None
    discovery_key: Optional[str] = None
    relay_address: Optional[str] = None
    traffic_routing_supported: bool = False


@dataclass
class Node:
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


class CoreServer(HTTPServer):
    def __init__(self, server_address, RequestHandlerClass, mqttc: mqtt.Client) -> None:
        super().__init__(server_address, RequestHandlerClass)
        # NOTE: In future this will most likely need to become a map from uuids to nodes so that it's possible
        # to implement 'GET /v1/meshnet/machines/{machineIdentifier}/map'
        self._known_machines: set[str] = set()
        self._mqttc = mqttc

    def _send_notification(self):
        message = {
            "message": {
                "data": {
                    "metadata": {
                        "message_id": str(uuid4()),
                    },
                    "event": {
                        "attributes": {"affected_machines": list(self._known_machines)}
                    },
                }
            }
        }

        msg_info = self._mqttc.publish("meshnet", json.dumps(message), qos=1)
        msg_info.wait_for_publish()

    def add_machine(self, node):
        self._known_machines.add(node.identifier)
        self._send_notification()

    def remove_machine(self, uid):
        self._known_machines.remove(uid)
        self._send_notification()


class CoreApiHandler(BaseHTTPRequestHandler):
    def __init__(self, request, client_address, server: CoreServer):
        self.server: CoreServer
        self.machines_path = "/v1/meshnet/machines"
        self.next_id_generator = count(1)
        super().__init__(request, client_address, server)

    def _set_headers(self):
        self.send_response(200)
        self.send_header("Content-type", "text/html")
        self.end_headers()

    def do_GET(self):
        self._set_headers()

    def do_HEAD(self):
        self._set_headers()

    def do_DELETE(self):
        if self.path.startswith(self.machines_path):
            self.handle_machines_delete()
        else:
            print(f"unsupported endpoint '{self.path}'")

    def do_POST(self):
        if self.path == self.machines_path:
            self.handle_register_machine()
        else:
            print(f"unsupported endpoint '{self.path}'")

    def handle_register_machine(self):
        content_length = int(self.headers["Content-Length"])
        post_data = self.rfile.read(content_length)
        print(f"The POST data: {post_data.decode()}")
        json_obj = json.loads(post_data)
        req = MachineCreateRequest(**json_obj)

        node = self.add_node(req)

        resp = json.dumps(asdict(node))
        self.send_response(201)
        self.end_headers()
        self.wfile.write(str.encode(resp))

    def add_node(self, req):
        uid = next(self.next_id_generator)

        identifier, hostname, ip_addresses = (
            str(uuid4()),
            f"everest{uid}-someuser.nord",
            [f"192.168.0.{uid}"],
        )
        node = Node(
            identifier=identifier,
            hostname=hostname,
            ip_addresses=ip_addresses,
            public_key=req.public_key,
            os=req.os,
            os_version=req.os_version,
            device_type=req.device_type,
            nickname=req.nickname,
            discovery_key=req.discovery_key,
            relay_address=req.relay_address,
            traffic_routing_supported=req.traffic_routing_supported,
        )

        self.server.add_machine(node)

        pprint(node)
        return node

    def handle_machines_delete(self):
        uid = self.path.removeprefix(self.machines_path)[1:]
        print("uuid:", uid)

        try:
            self.server.remove_machine(uid)
            print(f"{uid} removed")
            self.send_response(204)
        except KeyError:
            print(f"{uid} unknown")
            self.send_response(400)

        self.end_headers()


def run(mqttc, port=8080):
    server_address = ("", port)
    httpd = CoreServer(server_address, CoreApiHandler, mqttc)
    print("Starting httpd...")
    httpd.serve_forever()


def on_connect(_client, userdata, flags, reason_code, properties):
    print(
        f'Connected with result code userdata="{userdata}" flags="{flags}" reason_code="{reason_code}" properties="{properties}"'
    )


def on_message(_client, _userdata, msg):
    print("got a message:", msg.topic + " " + str(msg.payload))


def on_subscribe(_client, _userdata, mid, qos, _properties=None):
    print(f"subscribed mid={mid}, qos={qos}")


def main():
    print("Starting core api simulator")
    mqttc = mqtt.Client(
        mqtt.CallbackAPIVersion.VERSION2, client_id="sender", protocol=mqtt.MQTTv311
    )
    mqttc.on_connect = on_connect
    mqttc.on_message = on_message
    mqttc.on_subscribe = on_subscribe
    mqttc.connect("10.0.80.85", port=1883, keepalive=60)

    mqttc.loop_start()

    print("Mqtt connected")

    run(mqttc)

    mqttc.disconnect()
    mqttc.loop_stop()


if __name__ == "__main__":
    main()
