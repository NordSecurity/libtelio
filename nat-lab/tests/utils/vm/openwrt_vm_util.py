import asyncssh
import os
from tests.config import get_root_path, LAN_ADDR_MAP
from tests.utils.connection import Connection, ConnectionTag
from tests.utils.process import ProcessExecError

DIST_PATH = f"dist/openwrt/{os.getenv('TELIO_BIN_PROFILE')}/x86_64/{os.getenv('LIBTELIO_ENV_OPENWRT_RELEASE_BUILD_TAG')}/"
NATLAB_DATA_PATH = "nat-lab/data/"
OWR_CERT_PATH = "/etc/ssl/server_certificate/"
CERT_FILE_NAME = "test.pem"
NORDVPNLITE_OWR_NAME = "nordvpnlite_0.1.0-r1_x86_64.ipk"

# CDN
CDN_HOST = LAN_ADDR_MAP[ConnectionTag.DOCKER_OPENWRT_CDN]["primary"]
CDN_BASE_URL = f"http://{CDN_HOST}/nordvpnlite"
CDN_PUB_KEY_URL = f"{CDN_BASE_URL}/nordvpnlite-feed.pub"
OPENWRT_ARCH = "x86_64"
CDN_FEED_URL = f"{CDN_BASE_URL}/feeds/{OPENWRT_ARCH}"
CDN_WEB_ROOT = "/var/www/nordvpnlite/"
CDN_FEED_DIR = f"{CDN_WEB_ROOT}feeds/{OPENWRT_ARCH}/"

# OpenWrt VM
CUSTOM_FEEDS_CONF = "/etc/opkg/customfeeds.conf"


async def copy_artifacts_to_cdn(
    cdn_ssh_connection: asyncssh.SSHClientConnection,
) -> None:
    # Create feed directory structure on CDN
    await cdn_ssh_connection.run(f"mkdir -p {CDN_FEED_DIR}", check=True)

    # Feed artifacts go into the arch-specific directory
    feed_files = [
        (f"{DIST_PATH}{NORDVPNLITE_OWR_NAME}", CDN_FEED_DIR),
        (f"{DIST_PATH}Packages", CDN_FEED_DIR),
        (f"{DIST_PATH}Packages.gz", CDN_FEED_DIR),
        (f"{DIST_PATH}Packages.sig", CDN_FEED_DIR),
    ]

    # Pub key goes into the base directory
    root_files = [
        (f"{DIST_PATH}nordvpnlite-feed.pub", CDN_WEB_ROOT),
    ]

    for src, dst_dir in feed_files + root_files:
        filename = os.path.basename(src)
        await asyncssh.scp(
            get_root_path(src),
            (cdn_ssh_connection, f"{dst_dir}{filename}"),
        )


async def setup_openwrt_vm(
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
        await connection.create_process(
            ["wget", "-q", "-O", "/tmp/nordvpn-feed.pub", CDN_PUB_KEY_URL]
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


async def copy_binaries(
    connection: Connection,
) -> None:
    async with asyncssh.connect(
        CDN_HOST,
        username="root",
        password="",
        known_hosts=None,
        agent_path=None,
    ) as cdn_ssh_connection:
        await copy_artifacts_to_cdn(cdn_ssh_connection)
    await setup_openwrt_vm(connection)
