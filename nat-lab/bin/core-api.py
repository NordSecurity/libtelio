#!/usr/bin/python3

import json
import paho.mqtt.client as mqtt  # type: ignore # pylint: disable=import-error
import ssl
from dataclasses import asdict, dataclass
from enum import Enum
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, HTTPServer
from itertools import count
from typing import Dict, Optional
from uuid import uuid4

DERP_SERVER = {
    "region_code": "nl",
    "name": "Natlab #0001",
    "hostname": "derp-01",
    "ipv4": "10.0.10.1",
    "relay_port": 8765,
    "stun_port": 3479,
    "stun_plaintext_port": 3478,
    "public_key": "qK/ICYOGBu45EIGnopVu+aeHDugBrkLAZDroKGTuKU0=",  # NOTE: this is hardcoded key for transient docker container existing only during the tests
    "weight": 1,
}

CERTIFICATE_PATH = "/etc/ssl/server_certificate/server.pem"


class CoreApiErrorCode(Enum):
    MACHINE_ALREADY_EXISTS = 101117
    MACHINE_NOT_FOUND = 101102


@dataclass
class MachineCreateRequest:
    public_key: str
    hardware_identifier: str
    os: str
    os_version: str
    device_type: Optional[str] = None
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
        self._known_machines: Dict[str, Node] = {}
        self._mqttc = mqttc
        self._id_counter = count(1)

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
        self._known_machines[node.identifier] = node
        self._send_notification()

    def remove_machine(self, uid):
        if self._known_machines.pop(uid, None) is not None:
            self._send_notification()
            return True
        return False

    def get_machines(self):
        return self._known_machines

    def next_id(self):
        return next(self._id_counter)


class CoreApiHandler(BaseHTTPRequestHandler):
    def __init__(self, request, client_address, server: CoreServer):
        self.server: CoreServer
        self.machines_path = "/v1/meshnet/machines"
        super().__init__(request, client_address, server)

    def _set_headers(
        self, content_type="application/json", status_code: int = HTTPStatus.OK
    ):
        self.send_response(status_code)
        self.send_header("Content-type", content_type)
        self.end_headers()

    def _write_response(self, response, status_code: int = HTTPStatus.OK):
        self._set_headers(status_code=status_code)
        self.wfile.write(json.dumps(response).encode("utf-8"))

    def _send_error_response(
        self, error_code: CoreApiErrorCode, message: str, status_code: int
    ):
        error_response = {"errors": {"code": error_code.value, "message": message}}
        self._write_response(error_response, status_code)

    def do_GET(self):
        if self.path == "/":
            self.handle_root_path()
        elif self.path == self.machines_path:
            self.handle_get_machines()
        elif self.path.split("/")[-1] == "map":
            machine_id = self.path.split("/")[-2]
            self.handle_get_machine_map(machine_id)
        elif self.path == "/v1/health":
            self.handle_root_path()

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

    def do_PATCH(self):
        if self.path.startswith(self.machines_path):
            machine_id = self.path.removeprefix(self.machines_path + "/")
            self.handle_patch_machine(machine_id)

    def handle_root_path(self):
        self._set_headers()

    def handle_register_machine(self):
        content_length = int(self.headers["Content-Length"])
        post_data = self.rfile.read(content_length)
        print(f"The POST data: {post_data.decode()}")
        json_obj = json.loads(post_data)

        machines = self.server.get_machines().values()
        if any(machine.public_key == json_obj["public_key"] for machine in machines):
            self._send_error_response(
                CoreApiErrorCode.MACHINE_ALREADY_EXISTS,
                "Machine with this public key already exists",
                HTTPStatus.CONFLICT,
            )
            return

        req = MachineCreateRequest(**json_obj)
        node = self.add_node(req)
        self._write_response(asdict(node))

    def add_node(self, req):
        uid = self.server.next_id()
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
            device_type=req.device_type or "",
            nickname=req.nickname or "",
            discovery_key=req.discovery_key or "",
            relay_address=req.relay_address or "",
            traffic_routing_supported=req.traffic_routing_supported,
        )

        self.server.add_machine(node)

        return node

    def handle_machines_delete(self):
        uid = self.path.removeprefix(self.machines_path)[1:]

        if self.server.remove_machine(uid):
            self._set_headers(status_code=HTTPStatus.NO_CONTENT)
        else:
            self._send_error_response(
                CoreApiErrorCode.MACHINE_NOT_FOUND,
                "Machine not found",
                HTTPStatus.NOT_FOUND,
            )

    def handle_patch_machine(self, machine_id):
        machine = self.server.get_machines().get(machine_id)
        if not machine:
            self._send_error_response(
                CoreApiErrorCode.MACHINE_NOT_FOUND,
                "Machine not found",
                HTTPStatus.NOT_FOUND,
            )
            return

        content_length = int(self.headers["Content-Length"])
        patch_data = self.rfile.read(content_length)
        updates = json.loads(patch_data)

        updated = False
        for key, value in updates.items():
            if hasattr(machine, key):
                setattr(machine, key, value)
                updated = True

        if updated:
            self._set_headers()
            resp = json.dumps(asdict(machine))
            self.wfile.write(resp.encode("utf-8"))

    def handle_get_machines(self):
        machines = self.server.get_machines()
        self._write_response(
            [asdict(machine) for machine in machines.values()] if machines else []
        )

    def handle_get_machine_map(self, machine_id):
        machine = self.server.get_machines().get(machine_id)
        if not machine:
            self._send_error_response(
                CoreApiErrorCode.MACHINE_NOT_FOUND,
                "Machine not found",
                HTTPStatus.NOT_FOUND,
            )
            return
        self._write_response(self.get_meshmap(machine_id))

    def get_meshmap(self, machine_id):
        node = self.server.get_machines().get(machine_id)
        peers = [
            {
                **vars(peer_node),
                "is_local": True,
                "allow_incoming_connections": True,
            }
            for peer_id, peer_node in self.server.get_machines().items()
            if peer_id != machine_id
        ]

        return {
            **vars(node),
            "peers": peers,
            "dns": {"domains": [], "hosts": {}},
            "derp_servers": [DERP_SERVER],
        }


def run(mqttc, port=443):
    server_address = ("", port)
    httpd = CoreServer(server_address, CoreApiHandler, mqttc)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(
        certfile=CERTIFICATE_PATH,
    )
    httpd.socket = context.wrap_socket(httpd.socket, server_side=True)
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
    mqttc.tls_set(
        ca_certs=CERTIFICATE_PATH,
        certfile=CERTIFICATE_PATH,
        keyfile=CERTIFICATE_PATH,
        tls_version=ssl.PROTOCOL_TLSv1_2,
        cert_reqs=ssl.CERT_REQUIRED,
    )
    mqttc.connect("mqtt.nordvpn.com", port=8883, keepalive=60)

    mqttc.loop_start()

    print("Mqtt connected")

    run(mqttc)

    mqttc.disconnect()
    mqttc.loop_stop()


if __name__ == "__main__":
    main()
