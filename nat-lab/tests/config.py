import os
import platform
from typing import Dict, Union
from utils.bindings import Server, RelayState
from utils.connection import ConnectionTag

if platform.machine() != "x86_64":
    import pure_wg as Key
else:
    from python_wireguard import Key  # type: ignore

PROJECT_ROOT = os.path.dirname(os.path.realpath(__file__)) + "/../../"


# Get file path relative to project root
def get_root_path(path: str) -> str:
    return os.path.normpath(PROJECT_ROOT + path)


LAN_ADDR_MAP: Dict[ConnectionTag, Dict[str, str]] = {
    ConnectionTag.DOCKER_CONE_CLIENT_1: {"primary": "192.168.101.104", "secondary": ""},
    ConnectionTag.DOCKER_CONE_CLIENT_2: {"primary": "192.168.102.54", "secondary": ""},
    ConnectionTag.DOCKER_FULLCONE_CLIENT_1: {
        "primary": "192.168.109.88",
        "secondary": "",
    },
    ConnectionTag.DOCKER_FULLCONE_CLIENT_2: {
        "primary": "192.168.106.88",
        "secondary": "",
    },
    ConnectionTag.DOCKER_SYMMETRIC_CLIENT_1: {
        "primary": "192.168.103.88",
        "secondary": "",
    },
    ConnectionTag.DOCKER_SYMMETRIC_CLIENT_2: {
        "primary": "192.168.104.88",
        "secondary": "",
    },
    ConnectionTag.DOCKER_UPNP_CLIENT_1: {"primary": "192.168.105.88", "secondary": ""},
    ConnectionTag.DOCKER_UPNP_CLIENT_2: {"primary": "192.168.112.88", "secondary": ""},
    ConnectionTag.DOCKER_SHARED_CLIENT_1: {
        "primary": "192.168.101.67",
        "secondary": "192.168.113.67",
    },
    ConnectionTag.DOCKER_OPEN_INTERNET_CLIENT_1: {
        "primary": "10.0.11.2",
        "secondary": "",
    },
    ConnectionTag.DOCKER_OPEN_INTERNET_CLIENT_2: {
        "primary": "10.0.11.3",
        "secondary": "",
    },
    ConnectionTag.DOCKER_OPEN_INTERNET_CLIENT_DUAL_STACK: {
        "primary": "10.0.11.4",
        "secondary": "",
    },
    ConnectionTag.DOCKER_UDP_BLOCK_CLIENT_1: {
        "primary": "192.168.110.100",
        "secondary": "",
    },
    ConnectionTag.DOCKER_UDP_BLOCK_CLIENT_2: {
        "primary": "192.168.111.100",
        "secondary": "",
    },
    ConnectionTag.DOCKER_INTERNAL_SYMMETRIC_CLIENT: {
        "primary": "192.168.114.88",
        "secondary": "",
    },
    ConnectionTag.VM_WINDOWS_1: {
        "primary": "192.168.150.54",
        "secondary": "192.168.151.54",
    },
    ConnectionTag.VM_WINDOWS_2: {
        "primary": "192.168.152.54",
        "secondary": "192.168.153.54",
    },
    ConnectionTag.VM_MAC: {"primary": "192.168.154.54", "secondary": "192.168.155.54"},
    ConnectionTag.DOCKER_CONE_GW_1: {"primary": "192.168.101.254", "secondary": ""},
    ConnectionTag.DOCKER_CONE_GW_2: {"primary": "192.168.102.254", "secondary": ""},
    ConnectionTag.DOCKER_CONE_GW_3: {"primary": "192.168.113.254", "secondary": ""},
    ConnectionTag.VM_LINUX_FULLCONE_GW_1: {
        "primary": "192.168.109.254",
        "secondary": "10.0.254.9",
    },
    ConnectionTag.VM_LINUX_FULLCONE_GW_2: {
        "primary": "192.168.106.254",
        "secondary": "10.0.254.6",
    },
    ConnectionTag.DOCKER_SYMMETRIC_GW_1: {
        "primary": "192.168.103.254",
        "secondary": "",
    },
    ConnectionTag.DOCKER_SYMMETRIC_GW_2: {
        "primary": "192.168.104.254",
        "secondary": "",
    },
    ConnectionTag.DOCKER_UDP_BLOCK_GW_1: {
        "primary": "192.168.110.254",
        "secondary": "",
    },
    ConnectionTag.DOCKER_UDP_BLOCK_GW_2: {
        "primary": "192.168.111.254",
        "secondary": "",
    },
    ConnectionTag.DOCKER_UPNP_GW_1: {"primary": "192.168.105.254", "secondary": ""},
    ConnectionTag.DOCKER_UPNP_GW_2: {"primary": "192.168.112.254", "secondary": ""},
    ConnectionTag.DOCKER_OPENWRT_GW_1: {"primary": "192.168.115.254", "secondary": ""},
    ConnectionTag.DOCKER_INTERNAL_SYMMETRIC_GW: {
        "primary": "192.168.114.254",
        "secondary": "",
    },
    ConnectionTag.DOCKER_VPN_1: {"primary": "10.0.100.1", "secondary": ""},
    ConnectionTag.VM_LINUX_NLX_1: {"primary": "10.0.100.51", "secondary": ""},
    ConnectionTag.DOCKER_PHOTO_ALBUM: {"primary": "10.0.80.80", "secondary": ""},
    ConnectionTag.VM_OPENWRT_GW_1: {
        "primary": "192.168.115.254",
        "secondary": "10.0.254.14",
    },
    ConnectionTag.DOCKER_OPENWRT_CLIENT_1: {
        "primary": "192.168.115.100",
        "secondary": "",
    },
}

GW_ADDR_MAP: Dict[ConnectionTag, Dict[str, str]] = {
    ConnectionTag.VM_WINDOWS_1: {
        "primary": "192.168.150.254",
        "secondary": "192.168.151.254",
    },
    ConnectionTag.VM_WINDOWS_2: {
        "primary": "192.168.152.254",
        "secondary": "192.168.153.254",
    },
    ConnectionTag.VM_MAC: {
        "primary": "192.168.154.254",
        "secondary": "192.168.155.254",
    },
    ConnectionTag.VM_LINUX_NLX_1: {
        "primary": "",
        "secondary": "",
    },
    ConnectionTag.VM_LINUX_FULLCONE_GW_1: {
        "primary": "",
        "secondary": "",
    },
    ConnectionTag.VM_LINUX_FULLCONE_GW_2: {
        "primary": "",
        "secondary": "",
    },
}

LAN_ADDR_MAP_V6: Dict[ConnectionTag, str] = {
    ConnectionTag.DOCKER_OPEN_INTERNET_CLIENT_DUAL_STACK: (
        "2001:db8:85a4::dead:beef:ceed"
    ),
}

# Same as defined in `libtelio/nat-lab/docker-compose.yml`, 10.0.0.0/16
DOCKER_NETWORK_IP = "10.0.0.0"
DOCKER_NETWORK_MASK = "255.255.0.0"
STUN_SERVER = "10.0.1.1"
STUNV6_SERVER = "2001:db8:85a4::deed:6"

# Same as defined in `libtelio/nat-lab/provision_windows.ps1`
STUN_BINARY_PATH_WINDOWS = "C:/workspace/stunserver/release/stunclient.exe".replace(
    "/", "\\"
)
STUN_BINARY_PATH_MAC = "/var/root/stunserver/stunclient"

IPERF_BINARY_MAC = "/var/root/iperf3/iperf3"
IPERF_BINARY_WINDOWS = "C:/workspace/iperf3/iperf3.exe".replace("/", "\\")

WINDUMP_BINARY_WINDOWS = "C:/workspace/WinDump.exe".replace("/", "\\")

# JIRA issue: LLT-1664
# The directories between host and Docker container are shared via
# Docker volumes. Mounting `libtelio/dist` is a nogo, since when host
# filesystem directory dist/linux/release/x86_64 is deleted during
# ./run_local.py, the volume “loses” it’s link with host file system.
#
# JIRA issue: LLT-1702
# Seems like the best solution is to mount `libtelio` root directory,
# since its stable unlike `libtelio/dist`.
#
# Libtelio binary path inside Docker containers.
if os.getenv("TELIO_BIN_PROFILE") not in ["release", "debug"]:
    raise ValueError(
        'TELIO_BIN_PROFILE environment variable must be set to either "release" or'
        ' "debug".'
    )

if platform.system() == "Darwin":
    LIBTELIO_BINARY_PATH_DOCKER = (
        f"/libtelio/target/aarch64-unknown-linux-gnu/{os.getenv('TELIO_BIN_PROFILE')}/"
    )
else:
    LIBTELIO_BINARY_PATH_DOCKER = (
        f"/libtelio/dist/linux/{os.getenv('TELIO_BIN_PROFILE')}/"
        + platform.uname().machine
        + "/"
    )

# Libtelio binary path inside Windows and Mac VMs
LIBTELIO_BINARY_PATH_WINDOWS_VM = "C:/workspace/binaries/".replace("/", "\\")
LIBTELIO_BINARY_PATH_VM_MAC = "/var/root/workspace/binaries/"

UNIFFI_PATH_WINDOWS_VM = "C:/workspace/uniffi/".replace("/", "\\")
UNIFFI_PATH_VM_MAC = "/var/root/workspace/uniffi/"

LIBTELIO_LOCAL_IP = "10.5.0.2"

LIBTELIO_IPV6_WG_SUBNET = "fd74:656c:696f"
LIBTELIO_IPV6_WAN_SUBNET = "2001:db8:85a4"
LIBTELIO_IPV6_WAN_SUBNET_SZ = "48"

LIBTELIO_DNS_IPV4 = "100.64.0.2"
LIBTELIO_DNS_IPV6 = LIBTELIO_IPV6_WG_SUBNET + "::2"

LIBTELIO_EXIT_DNS_IPV4 = "100.64.0.3"
LIBTELIO_EXIT_DNS_IPV6 = LIBTELIO_IPV6_WG_SUBNET + "::3"

VPN_SERVER_SUBNET = "10.0.100.0/24"
PHOTO_ALBUM_IP = "10.0.80.80"
PHOTO_ALBUM_IPV6 = "2001:db8:85a4::adda:edde:5"
UDP_SERVER_IP4 = "10.0.80.81"
UDP_SERVER_IP6 = "2001:db8:85a4::adda:edde:6"


# vpn-01
WG_SERVER: Dict[str, Union[str, int]] = {
    "ipv4": "10.0.100.1",
    "port": 1023,  # Select some port in non-ephemeral port range to avoid clashes
    **dict(
        (key, str(val))
        for key, val in zip(("private_key", "public_key"), Key.key_pair())
    ),
    "container": "nat-lab-vpn-01-1",
}

# vpn-02
WG_SERVER_2: Dict[str, Union[str, int]] = {
    "ipv4": "10.0.100.2",
    "port": 1023,  # Select some port in non-ephemeral port range to avoid clashes
    **dict(
        (key, str(val))
        for key, val in zip(("private_key", "public_key"), Key.key_pair())
    ),
    "container": "nat-lab-vpn-02-1",
}

# nlx-01
NLX_SERVER: Dict[str, Union[str, int]] = {
    "ipv4": "10.0.100.51",
    "port": 1023,  # Select some port in non-ephemeral port range to avoid clashes
    **dict(
        (key, str(val))
        for key, val in zip(("private_key", "public_key"), Key.key_pair())
    ),
    "container": "nat-lab-nlx-01-1",
    "type": "nordlynx",
}

WG_SERVERS = [WG_SERVER, WG_SERVER_2, NLX_SERVER]

# TODO - bring here class DerpServer  from telio.py
# and replace dictionaries with objects

# DERP servers
DERP_PRIMARY = Server(
    region_code="nl",
    name="Natlab #0001",
    hostname="derp-01",
    ipv4="10.0.10.1",
    relay_port=8765,
    stun_port=3479,
    stun_plaintext_port=3478,
    public_key="qK/ICYOGBu45EIGnopVu+aeHDugBrkLAZDroKGTuKU0=",  # NOTE: this is hardcoded key for transient docker container existing only during the tests
    weight=1,
    use_plain_text=True,
    conn_state=RelayState.DISCONNECTED,
)

DERP_FAKE = Server(
    region_code="fk",
    name="Natlab #0002-fake",
    hostname="derp-00",
    ipv4="10.0.10.245",
    relay_port=8765,
    stun_port=3479,
    stun_plaintext_port=3478,
    public_key="aAY0rU8pW8LV3BJlY5u5WYH7nbAwS5H0mBMJppVDRGs=",  # NOTE: this is hardcoded key for transient docker container existing only during the tests
    weight=2,
    use_plain_text=True,
    conn_state=RelayState.DISCONNECTED,
)
# we kept it because the test on  mesh_api

DERP_SECONDARY = Server(
    region_code="de",
    name="Natlab #0002",
    hostname="derp-02",
    ipv4="10.0.10.2",
    relay_port=8765,
    stun_port=3479,
    stun_plaintext_port=3478,
    public_key="KmcnUJ7EfhCIF9o1S5ycShaNc3y1DmioKUlkMvEVoRI=",  # NOTE: this is hardcoded key for transient docker container existing only during the tests
    weight=3,
    use_plain_text=True,
    conn_state=RelayState.DISCONNECTED,
)

DERP_TERTIARY = Server(
    region_code="us",
    name="Natlab #0003",
    hostname="derp-03",
    ipv4="10.0.10.3",
    relay_port=8765,
    stun_port=3479,
    stun_plaintext_port=3478,
    public_key="A4ggUMw5DmMSjz1uSz3IkjM3A/CRgJxEHoGigwT0W3k=",  # NOTE: this is hardcoded key for transient docker container existing only during the tests
    weight=4,
    use_plain_text=True,
    conn_state=RelayState.DISCONNECTED,
)


# separating in objects
DERP_SERVERS = [DERP_PRIMARY, DERP_FAKE, DERP_SECONDARY, DERP_TERTIARY]

# port used by libdrop file sharing
LIBDROP_PORT = 49111

LINUX_INTERFACE_NAME = "tun10"

CORE_API_URL = "https://api.nordvpn.com"
CORE_API_IP = "10.0.80.86"
MQTT_BROKER_HOST = "mqtt.nordvpn.com"
MQTT_BROKER_IP = "10.0.80.85"
CORE_API_CA_CERTIFICATE_PATH = "/etc/ssl/server_certificate/test.pem"

# These credentials are only used in tests, never in production
CORE_API_CREDENTIALS = {
    "username": "token",
    "password": "48e9ef50178a68a716e38a9f9cd251e8be35e79a5c5f91464e92920425caa3d9",
}

CORE_API_BEARER_AUTHORIZATION_HEADER = (
    f"Bearer {CORE_API_CREDENTIALS['username']}:{CORE_API_CREDENTIALS['password']}"
)
