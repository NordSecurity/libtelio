import base64
import hashlib
import json
from typing import List, Any, Dict, cast

import aiohttp
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.x509.oid import ExtensionOID

from utils.connection import Connection, ConnectionTag
from helpers_vpn import VpnConfig
from helpers_fakefm import wait_for_service_active
import config
from utils.process import ProcessExecError

CERT_PATH = "/etc/ca-certificates/server-cert.pem.test"
NS_INFO_ADDRESS = "127.0.0.1"
NS_INFO_PORT = "6969"
NS_INFO_TOKEN = "elephant"

JsonDict = Dict[str, Any]

"""
Real ENS helpers
"""


async def _read_remote_file(nlx_conn: Connection, path: str) -> str:
    proc = nlx_conn.create_process(["cat", path])
    output = await proc.execute()
    return output.get_stdout()


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
        try:
            bc = cert.extensions.get_extension_for_oid(
                ExtensionOID.BASIC_CONSTRAINTS
            ).value
            is_ca = bc.ca
        except x509.ExtensionNotFound:
            is_ca = False

        if is_ca and cert.issuer == cert.subject:
            return cert
    return certs[-1]


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


async def _ns_call_api(
    nlx_conn: Connection,
    endpoint: str,
) -> Any:
    url = f"http://{NS_INFO_ADDRESS}:{NS_INFO_PORT}/api/v1/{endpoint}"
    cmd = [
        "curl",
        "-H",
        f"Authorization: Bearer {NS_INFO_TOKEN}",
        url,
    ]

    proc = nlx_conn.create_process(cmd)
    try:
        result = await proc.execute()
        stdout = result.get_stdout()
    except ProcessExecError as e:
        print(e.stderr)
        print(e.stdout)
        raise e

    assert stdout.strip(), f"NS api returned empty response for endpoint {endpoint}"

    return json.loads(stdout)


async def ns_set_maintenance_on(nlx_conn: Connection) -> None:
    data = await _ns_call_api(nlx_conn, "maintenance/on")
    state = data.get("state")
    assert (
        state == "MAINTENANCE"
    ), f"Unexpected NS state when enabling maintenance: {data}"


async def ns_set_maintenance_off(nlx_conn: Connection) -> None:
    data = await _ns_call_api(nlx_conn, "maintenance/off")
    state = data.get("state")
    message = data.get("message")
    assert state == "UNKNOWN", f"Unexpected NS state when disabling maintenance: {data}"
    assert (
        message == "Removing server from maintenance"
    ), f"Unexpected NS state when disabling maintenance: {data}"
    await wait_for_service_active(nlx_conn, "nlx-ns")


"""
Python stub helpers
"""


async def _request_json(method: str, url: str, **kwargs: Any) -> JsonDict:
    async with aiohttp.ClientSession() as session:
        http_method = getattr(session, method.lower())
        async with http_method(url, **kwargs) as response:
            if response.status != 200:
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


async def get_grpc_tls_root_certificate(
    vpn_ip: str,
    incorrect: bool = False,
) -> str:
    if incorrect:
        url = f"http://{vpn_ip}:8000/api/incorrect_root_certificate"
    else:
        url = f"http://{vpn_ip}:8000/api/grpc_tls_root_certificate"
    data = await make_get_json(url)
    return data["root_certificate"]


async def generate_incorrect_certificate() -> bytes:
    wg_conf = VpnConfig(config.WG_SERVER, ConnectionTag.DOCKER_VPN_1, True)
    vpn_ip = cast(str, wg_conf.server_conf["ipv4"])

    root_certificate_b64 = await get_grpc_tls_root_certificate(
        vpn_ip,
        incorrect=True,
    )
    return base64.b64decode(root_certificate_b64)


async def trigger_connection_error(vpn_ip, error_code, additional_info):
    data = {"code": error_code, "additional_info": additional_info}
    url = f"http://{vpn_ip}:8000/api/connection_error"
    await make_post(url, data)


async def set_vpn_server_private_key(vpn_ip, vpn_server_private_key):
    data = {"vpn_server_private_key": vpn_server_private_key}
    url = f"http://{vpn_ip}:8000/api/vpn_server_private_key"
    await make_post(url, data)
