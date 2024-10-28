#!/usr/bin/python3
import base64
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

MQTT_BROKER_HOST = "mqtt.nordvpn.com"
MQTT_BROKER_PORT = 8883

# Below credentials are intended only for testing purposes in nat-lab environment.
CORE_API_CREDENTIALS = {
    "username": "token",
    "password": "48e9ef50178a68a716e38a9f9cd251e8be35e79a5c5f91464e92920425caa3d9",
}
MQTT_CREDENTIALS = {
    "username": "mqtt_broker",
    "password": "9-A'.:vUM3FPTCABorsK}J4mM}/3898_",
}


class CoreApiErrorCode(Enum):
    MACHINE_ALREADY_EXISTS = 101117
    MACHINE_NOT_FOUND = 101102
    INVALID_CREDENTIALS = 100104
    AUTHORIZATION_HEADER_NOT_PROVIDED = 100105
    AUTHORIZATION_HEADER_INVALID = 100106


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
        self.notifications_path = "/v1/notifications/tokens"
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

    def validate_authorization_header(self, authorization_header, authorization_type):
        if not authorization_header:
            self._send_error_response(
                CoreApiErrorCode.AUTHORIZATION_HEADER_NOT_PROVIDED,
                "Authorization header not provided",
                HTTPStatus.BAD_REQUEST,
            )
            return False
        if not authorization_header.startswith(f"{authorization_type} "):
            self._send_error_response(
                CoreApiErrorCode.AUTHORIZATION_HEADER_INVALID,
                "Invalid authorization header",
                HTTPStatus.BAD_REQUEST,
            )
            return False
        return True

    def validate_bearer_token(self):
        auth_header = self.headers.get("Authorization")
        self.validate_authorization_header(auth_header, "Bearer")
        # Ignore "None" type warning as validation done in self.validate_authorization_header
        auth = auth_header.split(" ")[1]  # type: ignore[union-attr]
        username, token = auth.split(":", 1)
        if (
            username != CORE_API_CREDENTIALS["username"]
            or token != CORE_API_CREDENTIALS["password"]
        ):
            self._send_error_response(
                CoreApiErrorCode.INVALID_CREDENTIALS,
                "Invalid credentials",
                status_code=HTTPStatus.UNAUTHORIZED,
            )
            return False
        return True

    def validate_basic_authorization(self):
        auth_header = self.headers.get("Authorization")
        if not self.validate_authorization_header(auth_header, "Basic"):
            return False
        # Ignore "None" type warning as validation done in self.validate_authorization_header
        encoded_auth = auth_header.split(" ")[1]  # type: ignore[union-attr]
        decoded_auth = base64.b64decode(encoded_auth).decode("utf-8")
        username, token = decoded_auth.split(":", 1)

        if (
            CORE_API_CREDENTIALS["username"] == username
            and CORE_API_CREDENTIALS["password"] == token
        ):
            return True

        self._send_error_response(
            CoreApiErrorCode.INVALID_CREDENTIALS,
            "Invalid credentials",
            status_code=HTTPStatus.UNAUTHORIZED,
        )
        return False

    @staticmethod
    def requires_basic_authentication(func):
        def wrapper(self, *args, **kwargs):
            if not self.validate_basic_authorization():
                return None
            return func(self, *args, **kwargs)

        return wrapper

    @staticmethod
    def requires_bearer_token(func):
        def wrapper(self, *args, **kwargs):
            if not self.validate_bearer_token():
                return None
            return func(self, *args, **kwargs)

        return wrapper

    def do_GET(self):
        if self.path == "/v1/health":
            self.handle_root_path()
        elif self.path == self.machines_path:
            self.handle_get_machines()
        elif self.path.split("/")[-1] == "map":
            machine_id = self.path.split("/")[-2]
            self.handle_get_machine_map(machine_id)

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
        elif self.path == self.notifications_path:
            self.handle_get_notifications_token()
        else:
            print(f"unsupported endpoint '{self.path}'")

    def do_PATCH(self):
        if self.path.startswith(self.machines_path):
            machine_id = self.path.removeprefix(self.machines_path + "/")
            self.handle_patch_machine(machine_id)

    def handle_root_path(self):
        self._set_headers()

    @requires_bearer_token
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

    @requires_bearer_token
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

    @requires_bearer_token
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

    @requires_bearer_token
    def handle_get_machines(self):
        machines = self.server.get_machines()
        self._write_response(
            [asdict(machine) for machine in machines.values()] if machines else []
        )

    @requires_bearer_token
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

    @requires_basic_authentication
    def handle_get_notifications_token(self):
        content_length = int(self.headers["Content-Length"])
        post_data = self.rfile.read(content_length)
        print(f"The POST data: {post_data.decode()}")
        json.loads(post_data)
        response = {
            "endpoint": f"tcps://{MQTT_BROKER_HOST}:{MQTT_BROKER_PORT}",
            "username": MQTT_CREDENTIALS["username"],
            "password": MQTT_CREDENTIALS["password"],
            "expires_in": 60,
        }
        self._write_response(response)


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
    mqttc.username_pw_set(
        username=MQTT_CREDENTIALS["username"],
        password=MQTT_CREDENTIALS["password"],
    )
    mqttc.connect(host=MQTT_BROKER_HOST, port=MQTT_BROKER_PORT, keepalive=60)

    mqttc.loop_start()

    print("Mqtt connected")

    run(mqttc)

    mqttc.disconnect()
    mqttc.loop_stop()


if __name__ == "__main__":
    main()
