#!/usr/bin/python3
import base64
import json
import os
import paho.mqtt.client as mqtt  # type: ignore # pylint: disable=import-error
import random
import ssl
import string
from dataclasses import asdict, dataclass
from datetime import datetime
from enum import Enum
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, HTTPServer
from itertools import count
from mocked_core_api_servers_data import get_countries, get_servers
from typing import Any, Dict, Optional
from urllib.parse import urlparse, parse_qs
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

CERTIFICATE_PATH = "/etc/ssl/server_certificate/test.pem"
SERVER_PUBLIC_KEY_PATH = "/tmp/public_key_{country_id}.pub"

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

# Cache for service credentials to ensure consistency within a test run
_SERVICE_CREDENTIALS_CACHE: dict[str, Any] = {}


class CoreApiErrorCode(Enum):
    MACHINE_ALREADY_EXISTS = 101117
    MACHINE_NOT_FOUND = 101102
    INVALID_CREDENTIALS = 100104
    AUTHORIZATION_HEADER_NOT_PROVIDED = 100105
    AUTHORIZATION_HEADER_INVALID = 100106
    RESOURCE_NOT_FOUND = 404
    BAD_REQUEST = 400
    UNAUTHORIZED = 401


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

    def finish_request(self, request, client_address):
        """
        Override to ensure proper SSL shutdown

        This is necessary because some HTTP clients, like reqwest, require the server to properly close connections
        with close_notify when using TLS to prevent truncation attacks. HTTPServer doesn't send it by default, breaking
        some clients. This method override will make sure the close_notify is sent.
        """
        # Handle the request normally
        super().finish_request(request, client_address)

        # Ensure proper SSL shutdown
        try:
            request.unwrap()  # This sends close_notify
        except:
            pass  # Ignore errors during unwrap

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

    def clear_machines(self):
        self._known_machines = {}

    def get_machines(self):
        return self._known_machines

    def next_id(self):
        return next(self._id_counter)


class CoreApiHandler(BaseHTTPRequestHandler):
    def __init__(self, request, client_address, server: CoreServer):
        self.server: CoreServer
        self.machines_path = "/v1/meshnet/machines"
        self.notifications_path = "/v1/notifications/tokens"
        self.recommended_servers_path = "/v1/servers/recommendations"
        self.countries_path = "/v1/servers/countries"
        self.public_key_path = "/test/public-key"
        self.service_credentials_path = "/v1/users/services/credentials"
        self.reset_credentials_path = "/test/reset-credentials"
        self.reset_machines_path = "/test/reset-machines"
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
        elif self.path == self.countries_path:
            self.handle_get_countries()
        elif self.path.startswith(self.recommended_servers_path):
            parsed_url = urlparse(self.path)
            query_params = parse_qs(parsed_url.query)
            self.handle_get_servers(query_params)
        elif self.path == self.service_credentials_path:
            self.handle_service_credentials()

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
        elif self.path == self.public_key_path:
            self.handle_public_key()
        elif self.path == self.reset_credentials_path:
            self.handle_reset_credentials()
        elif self.path == self.reset_machines_path:
            self.handle_reset_machines()
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
        self._write_response(asdict(node), HTTPStatus.CREATED)

    def add_node(self, req):
        uid = self.server.next_id()
        identifier, hostname, ip_addresses = (
            str(uuid4()),
            f"everest{uid}-someuser.nord",
            [f"100.{random.randint(64, 127)}.{random.randint(0, 255)}.{8 + uid}"],
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
        self._write_response(response, status_code=HTTPStatus.CREATED)

    def handle_get_countries(self):
        countries = get_countries()
        self._write_response(countries)

    def handle_get_servers(self, query_params):
        print(f"Passed params: {query_params}")
        filters = {}
        for key, values in query_params.items():
            if key.startswith("filters[") and key.endswith("]"):
                filter_key = key[len("filters[") : -1]
                assert (
                    len(values) == 1
                ), f"More than one value is passed for {filter_key}: {values}"
                filters[filter_key] = values[0]
        country_id = filters.get("country_id", 1)
        if not os.path.isfile(SERVER_PUBLIC_KEY_PATH.format(country_id=country_id)):
            self._send_error_response(
                CoreApiErrorCode.RESOURCE_NOT_FOUND,
                "There is no saved public key for server. "
                "Use 'public-key' endpoint to save it first",
                HTTPStatus.NOT_FOUND,
            )
            return
        with open(
            SERVER_PUBLIC_KEY_PATH.format(country_id=country_id), "r", encoding="utf-8"
        ) as f:
            public_key = f.read()
        servers = get_servers(filters, public_key)
        if not servers:
            self._send_error_response(
                CoreApiErrorCode.RESOURCE_NOT_FOUND,
                "No vpn servers found for provided filters",
                HTTPStatus.NOT_FOUND,
            )
            return
        self._write_response([asdict(server) for server in servers])

    @requires_bearer_token
    def handle_public_key(self):
        # That is a test endpoint to save server public key
        # It is not a part of the official API
        content_length = int(self.headers["Content-Length"])
        post_data = self.rfile.read(content_length).decode("utf-8")
        json_obj = json.loads(post_data)
        pub_key = json_obj.get("public_key")
        country_id = json_obj.get("country_id", 1)
        if not pub_key:
            self._send_error_response(
                CoreApiErrorCode.BAD_REQUEST,
                "Required field 'public_key' is missing",
                HTTPStatus.BAD_REQUEST,
            )
            return
        with open(
            SERVER_PUBLIC_KEY_PATH.format(country_id=country_id), "w", encoding="utf-8"
        ) as f:
            f.write(pub_key)
        self.send_response(HTTPStatus.CREATED)
        self.end_headers()
        self.wfile.write(b"Public key saved")

    @requires_basic_authentication
    def handle_service_credentials(self):
        global _SERVICE_CREDENTIALS_CACHE
        current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        if not _SERVICE_CREDENTIALS_CACHE:
            _SERVICE_CREDENTIALS_CACHE = {
                "created_at": current_time,
                "updated_at": current_time,
                "username": "".join(
                    random.choices(string.ascii_letters + string.digits, k=24)
                ),
                "password": "".join(
                    random.choices(string.ascii_letters + string.digits, k=24)
                ),
                "nordlynx_key": base64.b64encode(random.randbytes(32)).decode("utf-8"),
                "id": random.randint(1, 10000),
            }

        response = {
            "id": _SERVICE_CREDENTIALS_CACHE["id"],
            "created_at": _SERVICE_CREDENTIALS_CACHE["created_at"],
            "updated_at": _SERVICE_CREDENTIALS_CACHE["updated_at"],
            "username": _SERVICE_CREDENTIALS_CACHE["username"],
            "password": _SERVICE_CREDENTIALS_CACHE["password"],
            "nordlynx_private_key": _SERVICE_CREDENTIALS_CACHE["nordlynx_key"],
        }
        self._write_response(response, HTTPStatus.OK)

    @requires_basic_authentication
    def handle_reset_credentials(self):
        global _SERVICE_CREDENTIALS_CACHE
        _SERVICE_CREDENTIALS_CACHE = {}
        self._set_headers(status_code=HTTPStatus.OK)
        self.wfile.write(b"Credentials cache cleared")

    @requires_basic_authentication
    def handle_reset_machines(self):
        self.server.clear_machines()
        self._set_headers(status_code=HTTPStatus.OK)
        self.wfile.write(b"Machines cache cleared")


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
