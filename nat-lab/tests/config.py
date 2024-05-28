import os
import platform
from typing import Dict, Union

if platform.machine() != "x86_64":
    import pure_wg as Key
else:
    from python_wireguard import Key  # type: ignore

PROJECT_ROOT = os.path.dirname(os.path.realpath(__file__)) + "/../../"


# Get file path relative to project root
def get_root_path(path: str) -> str:
    return os.path.normpath(PROJECT_ROOT + path)


# Same as defined in `Vagrantfile`
LINUX_VM_IP = "10.55.0.10"
MAC_VM_IP = "10.55.0.12"
WINDOWS_1_VM_IP = "10.55.0.13"
WINDOWS_2_VM_IP = "10.55.0.14"

LINUX_VM_PRIMARY_GATEWAY = "10.55.0.10"
LINUX_VM_SECONDARY_GATEWAY = "10.66.0.10"

PRIMARY_VM_NETWORK_PREFIX = "10.55.0"
SECONDARY_VM_NETWORK_PREFIX = "10.66.0"

# https://vagrant-libvirt.github.io/vagrant-libvirt/configuration.html#management-network
LIBVIRT_MANAGEMENT_NETWORK_PREFIX = "192.168.121"

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
if platform.system() == "Darwin":
    LIBTELIO_BINARY_PATH_DOCKER = "/libtelio/target/aarch64-unknown-linux-gnu/release/"
else:
    LIBTELIO_BINARY_PATH_DOCKER = (
        "/libtelio/dist/linux/release/" + platform.uname().machine + "/"
    )

# Libtelio binary path inside Windows and Mac VMs
LIBTELIO_BINARY_PATH_WINDOWS_VM = "C:/workspace/binaries/".replace("/", "\\")
LIBTELIO_BINARY_PATH_MAC_VM = "/var/root/workspace/binaries/"

UNIFFI_PATH_WINDOWS_VM = "C:/workspace/uniffi/".replace("/", "\\")
UNIFFI_PATH_MAC_VM = "/var/root/workspace/uniffi/"

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
PMTU_PROBE_HOST_IP4 = "10.0.80.84"
PMTU_PROBE_HOST_IP6 = "2001:db8:85a4::adda:edde:9"


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
DERP_PRIMARY = {
    "region_code": "nl",
    "name": "Natlab #0001",
    "hostname": "derp-01",
    "ipv4": "10.0.10.1",
    "relay_port": 8765,
    "stun_port": 3479,
    "stun_plaintext_port": 3478,
    "public_key": "qK/ICYOGBu45EIGnopVu+aeHDugBrkLAZDroKGTuKU0=",  # NOTE: this is hardcoded key for transient docker container existing only during the tests
    "weight": 1,
    "use_plain_text": True,
}

DERP_FAKE = {
    "region_code": "fk",
    "name": "Natlab #0002-fake",
    "hostname": "derp-00",
    "ipv4": "10.0.10.245",
    "relay_port": 8765,
    "stun_port": 3479,
    "stun_plaintext_port": 3478,
    "public_key": "aAY0rU8pW8LV3BJlY5u5WYH7nbAwS5H0mBMJppVDRGs=",  # NOTE: this is hardcoded key for transient docker container existing only during the tests
    "weight": 2,
    "use_plain_text": True,
}
# we kept it because the test on  mesh_api

DERP_SECONDARY = {
    "region_code": "de",
    "name": "Natlab #0002",
    "hostname": "derp-02",
    "ipv4": "10.0.10.2",
    "relay_port": 8765,
    "stun_port": 3479,
    "stun_plaintext_port": 3478,
    "public_key": "KmcnUJ7EfhCIF9o1S5ycShaNc3y1DmioKUlkMvEVoRI=",  # NOTE: this is hardcoded key for transient docker container existing only during the tests
    "weight": 3,
    "use_plain_text": True,
}

DERP_TERTIARY = {
    "region_code": "us",
    "name": "Natlab #0003",
    "hostname": "derp-03",
    "ipv4": "10.0.10.3",
    "relay_port": 8765,
    "stun_port": 3479,
    "stun_plaintext_port": 3478,
    "public_key": "A4ggUMw5DmMSjz1uSz3IkjM3A/CRgJxEHoGigwT0W3k=",  # NOTE: this is hardcoded key for transient docker container existing only during the tests
    "weight": 4,
    "use_plain_text": True,
}


# separating in objects
DERP_SERVERS = [DERP_PRIMARY, DERP_FAKE, DERP_SECONDARY, DERP_TERTIARY]

# port used by libdrop file sharing
LIBDROP_PORT = 49111
