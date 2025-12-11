import base64
import hashlib
from contextlib import asynccontextmanager
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from tests.helpers import request_json
from tests.helpers_fakefm import wait_for_service_active
from tests.utils.connection import Connection
from typing import List, Any, Dict

CERT_PATH = "/etc/ca-certificates/server-cert.pem.test"
ENS_INFO_PORT = "6969"
ENS_INFO_TOKEN = "elephant"

JsonDict = Dict[str, Any]


# Real ENS helpers


async def _read_remote_file(conn: Connection, path: str) -> str:
    proc = await conn.create_process(["cat", path]).execute()
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
    conn: Connection,
    cert_path: str = CERT_PATH,
) -> str:
    pem = await _read_remote_file(conn, cert_path)
    certs = _load_pem_chain(pem)

    leaf_cert = certs[0]
    leaf_der = leaf_cert.public_bytes(serialization.Encoding.DER)
    fingerprint = hashlib.sha256(leaf_der).hexdigest()
    return fingerprint


async def get_grpc_tls_root_certificate_from_server(
    conn: Connection,
    cert_path: str = CERT_PATH,
) -> str:
    pem = await _read_remote_file(conn, cert_path)
    certs = _load_pem_chain(pem)

    root_cert = _find_root_cert(certs)
    root_der = root_cert.public_bytes(serialization.Encoding.DER)

    encoded = base64.b64encode(root_der).decode("ascii")
    return encoded


async def _ens_call_api(vpn_ip: str, endpoint: str) -> Any:
    url = f"http://{vpn_ip}:{ENS_INFO_PORT}/api/v1/{endpoint}"
    headers = {"Authorization": f"Bearer {ENS_INFO_TOKEN}"}
    return await request_json("GET", url, headers=headers)


async def ens_set_maintenance(
    conn: Connection,
    vpn_ip: str,
    maintenance: bool,
) -> None:
    endpoint = "maintenance/on" if maintenance else "maintenance/off"
    data = await _ens_call_api(vpn_ip, endpoint)
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
        await wait_for_service_active(conn, "nlx-ns")


@asynccontextmanager
async def ens_maintenance(conn: Connection, vpn_ip: str):
    await ens_set_maintenance(conn, vpn_ip, maintenance=True)
    try:
        yield
    finally:
        await ens_set_maintenance(conn, vpn_ip, maintenance=False)


# Python stub helpers


async def make_post(url: str, data: Any) -> JsonDict:
    return await request_json("POST", url, json=data)


async def make_get_json(url: str) -> JsonDict:
    return await request_json("GET", url)


async def get_grpc_tls_fingerprint(vpn_ip: str) -> str:
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


async def generate_incorrect_certificate(vpn_ip: str) -> bytes:
    root_certificate_b64 = await get_incorrect_grpc_tls_root_certificate(vpn_ip)
    return base64.b64decode(root_certificate_b64)


async def trigger_connection_error(
    vpn_ip: str,
    error_code: int,
    additional_info: str,
) -> None:
    data = {"code": error_code, "additional_info": additional_info}
    url = f"http://{vpn_ip}:8000/api/connection_error"
    await make_post(url, data)


async def set_vpn_server_private_key(
    vpn_ip: str,
    vpn_server_private_key: str,
) -> None:
    data = {"vpn_server_private_key": vpn_server_private_key}
    url = f"http://{vpn_ip}:8000/api/vpn_server_private_key"
    await make_post(url, data)
