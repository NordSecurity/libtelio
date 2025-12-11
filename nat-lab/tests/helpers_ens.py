import aiohttp
import base64
import hashlib
import json
from contextlib import asynccontextmanager
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from http import HTTPStatus
from tests import config
from tests.helpers_fakefm import wait_for_service_active
from tests.helpers_vpn import VpnConfig
from tests.utils.connection import Connection, ConnectionTag
from typing import List, Any, Dict, cast

CERT_PATH = "/etc/ca-certificates/server-cert.pem.test"
ENS_INFO_ADDRESS = "127.0.0.1"
ENS_NS_INFO_PORT = "6969"
ENS_INFO_TOKEN = "elephant"

JsonDict = Dict[str, Any]


# Real ENS helpers


async def _read_remote_file(nlx_conn: Connection, path: str) -> str:
    proc = await nlx_conn.create_process(["cat", path]).execute()
    return proc.get_stdout()


def _load_pem_chain(pem_data: str) -> List[x509.Certificate]:
    certs: List[x509.Certificate] = []
    block: List[str] = []
    in_cert = False

    for line in pem_data.splitlines(keepends=True):
        if "BEGIN CERTIFICATE" in line:
            in_cert = True
            block = [line]
        elif "END CERTIFICATE" in line:
            block.append(line)
            pem_block = "".join(block).encode("ascii")
            cert = x509.load_pem_x509_certificate(pem_block)
            certs.append(cert)
            in_cert = False
            block = []
        elif in_cert:
            block.append(line)

    if not certs:
        raise ValueError("No certificates found in PEM data")

    return certs


def _find_root_cert(certs: List[x509.Certificate]) -> x509.Certificate:
    for cert in certs:
        if cert.issuer == cert.subject:
            return cert
    raise ValueError("No root certificate found in the provided chain")


async def get_grpc_tls_fingerprint_from_server(
    nlx_conn: Connection,
    cert_path: str = CERT_PATH,
) -> str:
    pem = await _read_remote_file(nlx_conn, cert_path)
    certs = _load_pem_chain(pem)

    leaf_cert = certs[0]
    leaf_der = leaf_cert.public_bytes(serialization.Encoding.DER)
    fingerprint = hashlib.sha256(leaf_der).hexdigest()
    return fingerprint


async def get_grpc_tls_root_certificate_from_server(
    nlx_conn: Connection,
    cert_path: str = CERT_PATH,
) -> str:
    pem = await _read_remote_file(nlx_conn, cert_path)
    certs = _load_pem_chain(pem)

    root_cert = _find_root_cert(certs)
    root_der = root_cert.public_bytes(serialization.Encoding.DER)

    encoded = base64.b64encode(root_der).decode("ascii")
    return encoded


async def _ens_call_api(
    nlx_conn: Connection,
    endpoint: str,
) -> Any:
    url = f"http://{ENS_INFO_ADDRESS}:{ENS_NS_INFO_PORT}/api/v1/{endpoint}"
    cmd = [
        "curl",
        "-H",
        f"Authorization: Bearer {ENS_INFO_TOKEN}",
        url,
    ]

    proc = await nlx_conn.create_process(cmd).execute()
    output = proc.get_stdout()

    assert output.strip(), f"NS api returned empty response for endpoint {endpoint}"

    return json.loads(output)


async def ens_set_maintenance(nlx_conn: Connection, maintenance: bool) -> None:
    endpoint = "maintenance/on" if maintenance else "maintenance/off"
    data = await _ens_call_api(nlx_conn, endpoint)
    state = data.get("state")

    if maintenance:
        assert (
            state == "MAINTENANCE"
        ), f"Unexpected NS state when enabling maintenance: {data}"
    else:
        message = data.get("message")
        assert (
            state == "UNKNOWN"
        ), f"Unexpected NS state when disabling maintenance: {data}"
        assert (
            message == "Removing server from maintenance"
        ), f"Unexpected NS state when disabling maintenance: {data}"
        await wait_for_service_active(nlx_conn, "nlx-ns")


@asynccontextmanager
async def ens_maintenance(nlx_conn: Connection):
    await ens_set_maintenance(nlx_conn, maintenance=True)
    try:
        yield
    finally:
        await ens_set_maintenance(nlx_conn, maintenance=False)


# Python stub helpers


async def _request_json(method: str, url: str, **kwargs: Any) -> JsonDict:
    async with aiohttp.ClientSession() as session:
        http_method = getattr(session, method.lower())
        async with http_method(url, **kwargs) as response:
            if response.status != HTTPStatus.OK:
                body = await response.text()
                raise RuntimeError(
                    f"{method} {url} failed with status {response.status}: {body}"
                )
            return await response.json()


async def make_post(url: str, data: Any) -> JsonDict:
    return await _request_json("POST", url, json=data)


async def make_get_json(url: str) -> JsonDict:
    return await _request_json("GET", url)


async def get_grpc_tls_fingerprint() -> str:
    wg_conf = VpnConfig(config.WG_SERVER, ConnectionTag.DOCKER_VPN_1, True)
    vpn_ip = str(wg_conf.server_conf["ipv4"])
    url = f"http://{vpn_ip}:8000/api/grpc_tls_fingerprint"
    data = await make_get_json(url)
    return data["fingerprint"]


async def get_grpc_tls_root_certificate(vpn_ip: str) -> str:
    url = f"http://{vpn_ip}:8000/api/grpc_tls_root_certificate"
    data = await make_get_json(url)
    return data["root_certificate"]


async def get_incorrect_grpc_tls_root_certificate(vpn_ip: str) -> str:
    url = f"http://{vpn_ip}:8000/api/incorrect_root_certificate"
    data = await make_get_json(url)
    return data["root_certificate"]


async def generate_incorrect_certificate() -> bytes:
    wg_conf = VpnConfig(config.WG_SERVER, ConnectionTag.DOCKER_VPN_1, True)
    vpn_ip = cast(str, wg_conf.server_conf["ipv4"])

    root_certificate_b64 = await get_incorrect_grpc_tls_root_certificate(vpn_ip)
    return base64.b64decode(root_certificate_b64)


async def trigger_connection_error(vpn_ip, error_code, additional_info):
    data = {"code": error_code, "additional_info": additional_info}
    url = f"http://{vpn_ip}:8000/api/connection_error"
    await make_post(url, data)


async def set_vpn_server_private_key(vpn_ip, vpn_server_private_key):
    data = {"vpn_server_private_key": vpn_server_private_key}
    url = f"http://{vpn_ip}:8000/api/vpn_server_private_key"
    await make_post(url, data)
