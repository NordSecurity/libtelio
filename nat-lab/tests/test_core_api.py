import json
import pytest
from config import CORE_API_CA_CERTIFICATE_PATH, CORE_API_URL
from contextlib import AsyncExitStack
from dataclasses import dataclass
from enum import Enum
from helpers import send_https_request, verify_uuid
from utils.connection_util import ConnectionTag, new_connection_by_tag


@dataclass
class MachineData:
    public_key: str
    hardware_identifier: str
    os: str
    os_version: str


class CoreApiErrorCode(Enum):
    MACHINE_ALREADY_EXISTS = 101117
    AUTHORIZATION_HEADER_NOT_PROVIDED = 100105
    INVALID_CREDENTIALS = 100104


peer_structure = {
    "identifier": str,
    "public_key": str,
    "hostname": str,
    "os": str,
    "os_version": str,
    "device_type": str,
    "nickname": str,
    "ip_addresses": [str],
    "discovery_key": str,
    "relay_address": str,
    "traffic_routing_supported": bool,
    "is_local": bool,
    "allow_incoming_connections": bool,
}


derp_structure = {
    "region_code": str,
    "name": str,
    "hostname": str,
    "ipv4": str,
    "relay_port": int,
    "stun_port": int,
    "stun_plaintext_port": int,
    "public_key": str,
    "weight": int,
}

CREDENTIALS_CONFIG = {
    "core_api_credentials": {
        "username": "token",
        "password": "48e9ef50178a68a716e38a9f9cd251e8be35e79a5c5f91464e92920425caa3d9",
    },
}

bearer_authorization_header = f"Bearer {CREDENTIALS_CONFIG['core_api_credentials']['username']}:{CREDENTIALS_CONFIG['core_api_credentials']['password']}"


def validate_dict_structure(data_to_validate, expected_data_structure) -> None:
    for key, expected_type in expected_data_structure.items():
        assert key in data_to_validate, f"Missing key: {key}"
        value = data_to_validate[key]

        if isinstance(expected_type, list):
            assert isinstance(value, list), f"Key '{key}' should be a list."
            item_type = expected_type[0]
            for item in value:
                assert isinstance(
                    item, item_type
                ), f"Items in list '{key}' should be of type {item_type}, but got {type(item)}"

        elif isinstance(expected_type, dict):
            assert isinstance(value, dict), f"Key '{key}' should be a dict."
            validate_dict_structure(value, expected_type)

        elif isinstance(expected_type, type):
            assert isinstance(
                value, expected_type
            ), f"Key '{key}' should be of type {expected_type}, but got {type(value)}"

        else:
            raise ValueError(f"Unexpected type for key '{key}': {expected_type}")


async def clean_up_machines(connection, server_host):
    machines = await send_https_request(
        connection,
        f"{server_host}/v1/meshnet/machines",
        "GET",
        CORE_API_CA_CERTIFICATE_PATH,
        authorization_header=bearer_authorization_header,
    )

    for machine in machines:
        await send_https_request(
            connection,
            f"{server_host}/v1/meshnet/machines/{machine['identifier']}",
            "DELETE",
            CORE_API_CA_CERTIFICATE_PATH,
            expect_response=False,
            authorization_header=bearer_authorization_header,
        )


linux_vm = MachineData(
    public_key="linux-vm-public-key",
    hardware_identifier="linux-vm-hardware-identifier",
    os="linux",
    os_version="Ubuntu 22.04; kernel=5.15.0-78-generic",
)

windows_vm = MachineData(
    public_key="windows-vm-public-key",
    hardware_identifier="linux-vm-hardware-identifier",
    os="windows",
    os_version="Windows 11; kernel=10.0.22621.2283",
)


@pytest.fixture(name="machine_data")
def fixture_machine_data(request):
    return request.param


@pytest.fixture(name="server_host")
def fixture_server_host():
    return CORE_API_URL


@pytest.fixture(name="registered_machines")
async def fixture_register_machine(server_host, machine_data):
    async with AsyncExitStack() as exit_stack:
        connection = await exit_stack.enter_async_context(
            new_connection_by_tag(ConnectionTag.DOCKER_CONE_CLIENT_1)
        )

        await clean_up_machines(connection, server_host)

        registered_machines = []

        for data in machine_data:
            payload = json.dumps(data.__dict__)

            response_data = await send_https_request(
                connection,
                f"{server_host}/v1/meshnet/machines",
                "POST",
                CORE_API_CA_CERTIFICATE_PATH,
                data=payload,
                authorization_header=bearer_authorization_header,
            )
            registered_machines.append(response_data)

        return registered_machines


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "machine_data",
    [[
        linux_vm,
        windows_vm,
    ]],
    indirect=True,
)
async def test_register_multiple_machines(registered_machines, machine_data):
    assert len(registered_machines) == 2
    for machine, data in zip(registered_machines, machine_data):
        verify_uuid(machine["identifier"])
        assert machine["public_key"] == data.public_key
        assert machine["os"] == data.os
        assert machine["os_version"] == data.os_version
        assert "hostname" in machine
        assert "device_type" in machine
        assert "nickname" in machine
        assert "ip_addresses" in machine
        assert "discovery_key" in machine
        assert "relay_address" in machine
        assert not machine["traffic_routing_supported"]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "machine_data",
    [[
        linux_vm,
        windows_vm,
    ]],
    indirect=True,
)
async def test_get_all_machines(server_host, registered_machines, machine_data):
    async with AsyncExitStack() as exit_stack:
        connection = await exit_stack.enter_async_context(
            new_connection_by_tag(ConnectionTag.DOCKER_CONE_CLIENT_1)
        )

        response_data = await send_https_request(
            connection,
            f"{server_host}/v1/meshnet/machines",
            "GET",
            CORE_API_CA_CERTIFICATE_PATH,
            authorization_header=bearer_authorization_header,
        )

        assert isinstance(response_data, list)
        assert len(response_data) == 2

        for machine, data in zip(registered_machines, machine_data):
            verify_uuid(machine["identifier"])
            assert machine["public_key"] == data.public_key
            assert machine["os"] == data.os
            assert machine["os_version"] == data.os_version


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "machine_data",
    [[linux_vm]],
    indirect=True,
)
async def test_update_registered_machine_data(
    server_host, registered_machines, machine_data
):
    async with AsyncExitStack() as exit_stack:
        connection = await exit_stack.enter_async_context(
            new_connection_by_tag(ConnectionTag.DOCKER_CONE_CLIENT_1)
        )

        original_data = machine_data[0]

        machine_data_to_update = {
            "nickname": "Updated Machine",
            "os_version": "5.12",
        }

        payload = json.dumps(machine_data_to_update)

        for machine in registered_machines:

            response_data = await send_https_request(
                connection,
                f"{server_host}/v1/meshnet/machines/{machine['identifier']}",
                "PATCH",
                CORE_API_CA_CERTIFICATE_PATH,
                data=payload,
                authorization_header=bearer_authorization_header,
            )

            assert response_data["nickname"] == machine_data_to_update["nickname"]
            assert response_data["os_version"] == machine_data_to_update["os_version"]

            assert response_data["public_key"] == original_data.public_key
            assert response_data["os"] == original_data.os


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "machine_data",
    [[linux_vm]],
    indirect=True,
)
# pylint: disable=unused-argument
async def test_delete_registered_machine(
    server_host, registered_machines, machine_data
):
    async with AsyncExitStack() as exit_stack:
        connection = await exit_stack.enter_async_context(
            new_connection_by_tag(ConnectionTag.DOCKER_CONE_CLIENT_1)
        )

        machine = registered_machines[0]

        await send_https_request(
            connection,
            f"{server_host}/v1/meshnet/machines/{machine['identifier']}",
            "DELETE",
            CORE_API_CA_CERTIFICATE_PATH,
            expect_response=False,
            authorization_header=bearer_authorization_header,
        )

        get_response_data = await send_https_request(
            connection,
            f"{server_host}/v1/meshnet/machines",
            "GET",
            CORE_API_CA_CERTIFICATE_PATH,
            authorization_header=bearer_authorization_header,
        )

        assert len(get_response_data) == 0


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "machine_data",
    [[
        linux_vm,
        windows_vm,
    ]],
    indirect=True,
)
# pylint: disable=unused-argument
async def test_get_mesh_map(server_host, registered_machines, machine_data):
    async with AsyncExitStack() as exit_stack:
        connection = await exit_stack.enter_async_context(
            new_connection_by_tag(ConnectionTag.DOCKER_CONE_CLIENT_1)
        )

        for machine in registered_machines:

            response_data = await send_https_request(
                connection,
                f"{server_host}/v1/meshnet/machines/{machine['identifier']}/map",
                "GET",
                CORE_API_CA_CERTIFICATE_PATH,
                authorization_header=bearer_authorization_header,
            )

            assert isinstance(response_data["peers"], list)
            assert len(response_data["peers"]) == 1
            for peer in response_data["peers"]:
                validate_dict_structure(peer, peer_structure)

            assert isinstance(response_data["derp_servers"], list)
            for derp_server in response_data["derp_servers"]:
                validate_dict_structure(derp_server, derp_structure)


async def test_not_able_to_register_same_machine_twice(server_host):
    async with AsyncExitStack() as exit_stack:
        connection = await exit_stack.enter_async_context(
            new_connection_by_tag(ConnectionTag.DOCKER_CONE_CLIENT_1)
        )
        await clean_up_machines(connection, server_host)

        payload = json.dumps(linux_vm.__dict__)

        await send_https_request(
            connection,
            f"{server_host}/v1/meshnet/machines",
            "POST",
            CORE_API_CA_CERTIFICATE_PATH,
            data=payload,
            expect_response=False,
            authorization_header=bearer_authorization_header,
        )

        response_data = await send_https_request(
            connection,
            f"{server_host}/v1/meshnet/machines",
            "POST",
            CORE_API_CA_CERTIFICATE_PATH,
            data=payload,
            authorization_header=bearer_authorization_header,
        )

        assert (
            response_data["errors"]["code"]
            == CoreApiErrorCode.MACHINE_ALREADY_EXISTS.value
        )
        assert (
            response_data["errors"]["message"]
            == "Machine with this public key already exists"
        )


@pytest.mark.parametrize(
    "server_host, endpoint, method",
    [
        (CORE_API_URL, "/v1/meshnet/machines", "POST"),
        (CORE_API_URL, "/v1/meshnet/machines", "GET"),
        (CORE_API_URL, "/v1/meshnet/machines/uid/map", "GET"),
        (CORE_API_URL, "/v1/meshnet/machines/uid", "DELETE"),
        (CORE_API_URL, "/v1/meshnet/machines/uid", "PATCH"),
        (CORE_API_URL, "/v1/notifications/token", "POST"),
    ],
)
async def test_endpoints_requires_authorization_header(server_host, endpoint, method):
    async with AsyncExitStack() as exit_stack:
        connection = await exit_stack.enter_async_context(
            new_connection_by_tag(ConnectionTag.DOCKER_CONE_CLIENT_1)
        )
        url = f"{server_host}/{endpoint}"
        payload: dict[str, str] = {}
        if method == "GET":
            response_data = await send_https_request(
                connection,
                url,
                method,
                CORE_API_CA_CERTIFICATE_PATH,
                expect_response=True,
            )
        else:
            response_data = await send_https_request(
                connection,
                url,
                method,
                CORE_API_CA_CERTIFICATE_PATH,
                data=payload,
            )
        assert (
            response_data["errors"]["code"]
            == CoreApiErrorCode.AUTHORIZATION_HEADER_NOT_PROVIDED.value
        )
        assert response_data["errors"]["message"] == "Authorization header not provided"


@pytest.mark.parametrize(
    "server_host, endpoint, method",
    [
        (CORE_API_URL, "/v1/meshnet/machines", "POST"),
        (CORE_API_URL, "/v1/meshnet/machines", "GET"),
        (CORE_API_URL, "/v1/meshnet/machines/uid/map", "GET"),
        (CORE_API_URL, "/v1/meshnet/machines/uid", "DELETE"),
        (CORE_API_URL, "/v1/meshnet/machines/uid", "PATCH"),
    ],
)
async def test_not_able_to_pass_authorization_with_invalid_bearer_token(
    server_host, endpoint, method
):
    async with AsyncExitStack() as exit_stack:
        connection = await exit_stack.enter_async_context(
            new_connection_by_tag(ConnectionTag.DOCKER_CONE_CLIENT_1)
        )
        authorization_header = "Bearer token:11111"
        url = f"{server_host}/{endpoint}"
        payload: dict[str, str] = {}
        if method == "GET":
            response_data = await send_https_request(
                connection,
                url,
                method,
                CORE_API_CA_CERTIFICATE_PATH,
                authorization_header=authorization_header,
                expect_response=True,
            )
        else:
            response_data = await send_https_request(
                connection,
                url,
                method,
                CORE_API_CA_CERTIFICATE_PATH,
                authorization_header=authorization_header,
                data=payload,
            )
        assert (
            response_data["errors"]["code"]
            == CoreApiErrorCode.INVALID_CREDENTIALS.value
        )
        assert response_data["errors"]["message"] == "Invalid credentials"


@pytest.mark.parametrize(
    "server_host, endpoint, method",
    [
        (CORE_API_URL, "/v1/notifications/token", "POST"),
    ],
)
async def test_not_able_to_pass_authorization_with_invalid_basic_auth_credentials(
    server_host, endpoint, method
):
    async with AsyncExitStack() as exit_stack:
        connection = await exit_stack.enter_async_context(
            new_connection_by_tag(ConnectionTag.DOCKER_CONE_CLIENT_1)
        )
        authorization_header = "Basic dG9rZW46Y0hkaw=="  # token:pwd
        url = f"{server_host}/{endpoint}"
        payload: dict[str, str] = {}
        response_data = await send_https_request(
            connection,
            url,
            method,
            CORE_API_CA_CERTIFICATE_PATH,
            authorization_header=authorization_header,
            data=payload,
        )
        assert (
            response_data["errors"]["code"]
            == CoreApiErrorCode.INVALID_CREDENTIALS.value
        )
        assert response_data["errors"]["message"] == "Invalid credentials"
