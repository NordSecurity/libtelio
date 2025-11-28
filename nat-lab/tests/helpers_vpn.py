from dataclasses import dataclass
from tests import config
from tests.telio import Client
from tests.utils import stun
from tests.utils.connection import Connection, ConnectionTag
from tests.utils.ping import ping
from typing import Optional, Dict, Union

VAGRANT_LIBVIRT_MANAGEMENT_IP = "192.168.121"


async def connect_vpn(
    client_conn: Connection,
    vpn_connection: Optional[Connection],
    client: Client,
    client_meshnet_ip: str,
    wg_server: dict,
) -> None:
    await client.connect_to_vpn(
        wg_server["ipv4"], wg_server["port"], wg_server["public_key"]
    )

    await ping(client_conn, config.PHOTO_ALBUM_IP)

    if vpn_connection is not None:
        await ping(vpn_connection, client_meshnet_ip)

    ip = await stun.get(client_conn, config.STUN_SERVER)
    assert ip == wg_server["ipv4"], f"wrong public IP when connected to VPN {ip}"


@dataclass
class VpnConfig:
    server_conf: Dict[str, Union[str, int]]
    conn_tag: ConnectionTag
    # pinging the client is not a requirement and requires routing setup which might not be present
    should_ping_client: bool
