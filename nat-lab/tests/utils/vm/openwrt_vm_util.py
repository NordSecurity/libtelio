import asyncssh
import os
from tests.config import get_root_path, LAN_ADDR_MAP
from tests.utils.connection import Connection, ConnectionTag
from tests.utils.process import ProcessExecError

_PROFILE = os.getenv("TELIO_BIN_PROFILE")
NATLAB_DATA_PATH = "nat-lab/data/"
OWR_CERT_PATH = "/etc/ssl/server_certificate/"
CERT_FILE_NAME = "test.pem"

DIST_PATH = f"dist/openwrt/{_PROFILE}/x86_64/"

NORDVPNLITE_IPK_NAME = "nordvpnlite_0.1.0-r1_x86_64.ipk"

NORDVPNLITE_APK_NAME = "nordvpnlite-0.1.0-r1.apk"

# CDN
CDN_HOST = LAN_ADDR_MAP[ConnectionTag.DOCKER_OPENWRT_CDN]["primary"]
CDN_BASE_URL = f"http://{CDN_HOST}/nordvpnlite"
OPENWRT_ARCH = "x86_64"
CDN_FEED_URL = f"{CDN_BASE_URL}/feeds/{OPENWRT_ARCH}"

PUB_KEY_NAME_OPKG = "nordvpnlite-feed.pub"
PUB_KEY_NAME_APK = "nordvpnlite-apk.rsa.pub"
CDN_WEB_ROOT = "/var/www/nordvpnlite/"
CDN_FEED_DIR = f"{CDN_WEB_ROOT}feeds/{OPENWRT_ARCH}/"

# OpenWrt VM
CUSTOM_FEEDS_CONF = "/etc/opkg/customfeeds.conf"


OPKG_CDN_FILES = [
    (f"{DIST_PATH}{NORDVPNLITE_IPK_NAME}", CDN_FEED_DIR),
    (f"{DIST_PATH}Packages", CDN_FEED_DIR),
    (f"{DIST_PATH}Packages.gz", CDN_FEED_DIR),
    (f"{DIST_PATH}Packages.sig", CDN_FEED_DIR),
    (f"{DIST_PATH}{PUB_KEY_NAME_OPKG}", CDN_WEB_ROOT),
]

APK_CDN_FILES = [
    (f"{DIST_PATH}{NORDVPNLITE_APK_NAME}", CDN_FEED_DIR),
    (f"{DIST_PATH}packages.adb", CDN_FEED_DIR),
    (f"{DIST_PATH}{PUB_KEY_NAME_APK}", CDN_WEB_ROOT),
]


async def copy_artifacts_to_cdn(
    cdn_ssh_connection: asyncssh.SSHClientConnection,
    files: list[tuple[str, str]],
) -> None:
    await cdn_ssh_connection.run(f"mkdir -p {CDN_FEED_DIR}", check=True)
    for src, dst_dir in files:
        filename = os.path.basename(src)
        await asyncssh.scp(
            get_root_path(src),
            (cdn_ssh_connection, f"{dst_dir}{filename}"),
        )


async def setup_openwrt_vm_opkg(
    connection: Connection,
) -> None:
    try:
        # 0. Ensure clean state
        try:
            await connection.create_process(["opkg", "remove", "nordvpnlite"]).execute()
        except ProcessExecError:
            pass
        await connection.create_process(
            ["sh", "-c", f"> {CUSTOM_FEEDS_CONF}"]
        ).execute()

        # Copy core-api test certificate directly to the VM
        await connection.create_process(["mkdir", "-p", OWR_CERT_PATH]).execute()
        await connection.upload_file(
            get_root_path(f"{NATLAB_DATA_PATH}core_api/{CERT_FILE_NAME}"),
            f"{OWR_CERT_PATH}{CERT_FILE_NAME}",
        )

        # 1. Add the signing key
        pub_key_url = f"{CDN_BASE_URL}/{PUB_KEY_NAME_OPKG}"
        await connection.create_process(
            ["wget", "-q", "-O", "/tmp/nordvpn-feed.pub", pub_key_url]
        ).execute()
        await connection.create_process(
            ["opkg-key", "add", "/tmp/nordvpn-feed.pub"]
        ).execute()
        await connection.create_process(["rm", "/tmp/nordvpn-feed.pub"]).execute()

        # 2. Disable default feeds (no internet access in nat-lab)
        await connection.create_process(
            ["sh", "-c", "> /etc/opkg/distfeeds.conf"]
        ).execute()

        # 3. Add the feed
        await connection.create_process([
            "sh",
            "-c",
            f'echo "src/gz nordvpn {CDN_FEED_URL}" > {CUSTOM_FEEDS_CONF}',
        ]).execute()

        # 4. Install
        await connection.create_process(["opkg", "update"]).execute()
        await connection.create_process(["opkg", "install", "nordvpnlite"]).execute()

        # 5. Verify installation
        await connection.create_process(["nordvpnlite", "--version"]).execute()

    except ProcessExecError as e:
        raise RuntimeError(f"Feed setup/install failed: {e}") from e


async def setup_openwrt_vm_apk(
    connection: Connection,
) -> None:
    try:
        # 0. Ensure clean state
        try:
            await connection.create_process(["apk", "del", "nordvpnlite"]).execute()
        except ProcessExecError:
            pass

        # Copy core-api test certificate directly to the VM
        await connection.create_process(["mkdir", "-p", OWR_CERT_PATH]).execute()
        await connection.upload_file(
            get_root_path(f"{NATLAB_DATA_PATH}core_api/{CERT_FILE_NAME}"),
            f"{OWR_CERT_PATH}{CERT_FILE_NAME}",
        )

        # 1. Add the signing key
        pub_key_url = f"{CDN_BASE_URL}/{PUB_KEY_NAME_APK}"
        await connection.create_process(
            ["wget", "-q", "-O", f"/etc/apk/keys/{PUB_KEY_NAME_APK}", pub_key_url]
        ).execute()

        # 2. Disable default repos (no internet access in nat-lab)
        await connection.create_process(
            ["sh", "-c", "> /etc/apk/repositories"]
        ).execute()
        await connection.create_process(
            ["sh", "-c", "rm -f /etc/apk/repositories.d/*"]
        ).execute()

        # 3. Add the feed as a repository
        await connection.create_process(
            ["mkdir", "-p", "/etc/apk/repositories.d"]
        ).execute()
        await connection.create_process([
            "sh",
            "-c",
            f'echo "{CDN_FEED_URL}/packages.adb" > /etc/apk/repositories.d/nordvpn.list',
        ]).execute()

        # 4. Install
        await connection.create_process(["apk", "update"]).execute()
        await connection.create_process(["apk", "add", "nordvpnlite"]).execute()

        # 5. Verify installation
        await connection.create_process(["nordvpnlite", "--version"]).execute()

    except ProcessExecError as e:
        raise RuntimeError(f"Feed setup/install failed: {e}") from e


async def copy_binaries(
    connection: Connection,
    tag: ConnectionTag,
) -> None:
    async with asyncssh.connect(
        CDN_HOST,
        username="root",
        password="",
        known_hosts=None,
        agent_path=None,
    ) as cdn_ssh_connection:
        if tag == ConnectionTag.VM_OPENWRT_GW_2:
            await copy_artifacts_to_cdn(cdn_ssh_connection, APK_CDN_FILES)
            await setup_openwrt_vm_apk(connection)
        else:
            await copy_artifacts_to_cdn(cdn_ssh_connection, OPKG_CDN_FILES)
            await setup_openwrt_vm_opkg(connection)
