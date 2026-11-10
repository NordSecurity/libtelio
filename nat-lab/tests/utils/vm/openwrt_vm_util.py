import asyncssh
import glob
import os
from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import StrEnum
from tests.config import get_root_path, LAN_ADDR_MAP
from tests.utils.connection import Connection, ConnectionTag
from tests.utils.process import ProcessExecError
from typing import Optional

_PROFILE = os.getenv("TELIO_BIN_PROFILE")

NATLAB_DATA_PATH = "nat-lab/data/"
OWR_CERT_PATH = "/etc/ssl/server_certificate/"
CERT_FILE_NAME = "test.pem"

# CDN
CDN_HOST = LAN_ADDR_MAP[ConnectionTag.DOCKER_OPENWRT_CDN]["primary"]
CDN_BASE_URL = f"http://{CDN_HOST}/nordvpnlite"
CDN_WEB_ROOT = "/var/www/nordvpnlite/"

CUSTOM_FEEDS_CONF = "/etc/opkg/customfeeds.conf"

_USE_FEED = "GITLAB_CI" in os.environ


class PkgManager(StrEnum):
    OPKG = "opkg"
    APK = "apk"


@dataclass(frozen=True)
class OpenwrtVmConfig:
    version: str
    cdn_arch: str
    dist_dir: str
    pkg_manager: PkgManager
    # `--arch` of libtelio-build's ci/build.sh
    build_arch: str

    @property
    def dist_path(self) -> str:
        return f"dist/openwrt/{_PROFILE}/{self.dist_dir}/{self.version}/"

    @property
    def local_dist_path(self) -> str:
        return f"dist/openwrt/{_PROFILE}/{self.build_arch}/"

    @property
    def feed_url(self) -> str:
        return f"{CDN_BASE_URL}/feeds/{self.cdn_arch}"

    @property
    def feed_dir(self) -> str:
        return f"{CDN_WEB_ROOT}feeds/{self.cdn_arch}/"


class _OpenwrtPackageManager(ABC):
    PKG_EXT: str

    def __init__(self, connection: Connection, cfg: OpenwrtVmConfig):
        self._conn = connection
        self._cfg = cfg

    @abstractmethod
    def cdn_files(self) -> list[tuple[str, str]]: ...

    def local_package(self) -> str:
        pattern = get_root_path(
            f"{self._cfg.local_dist_path}nordvpnlite*.{self.PKG_EXT}"
        )
        matches = glob.glob(pattern)
        if len(matches) != 1:
            debug_flag = " --debug" if _PROFILE == "debug" else ""
            raise RuntimeError(
                f"Expected exactly one package matching {pattern}, found"
                f" {matches}. Build it from libtelio-build with:"
                f" LIBTELIO_ENV_OPENWRT_RELEASE_BUILD_TAG={self._cfg.version}"
                f" ci/build.sh --default openwrt --arch {self._cfg.build_arch}"
                f"{debug_flag} --ipk-package"
            )
        return matches[0]

    async def install_nordvpnlite(self, local_pkg_path: Optional[str] = None) -> None:
        """Install from the CDN feed, or from `local_pkg_path` when given."""
        try:
            await self._uninstall_existing()
            await self._copy_test_certificate()
            if local_pkg_path is None:
                await self._add_signing_key()
                await self._disable_default_feeds()
                await self._add_custom_feed()
                await self._update_and_install()
            else:
                remote_pkg_path = f"/tmp/{os.path.basename(local_pkg_path)}"
                await self._conn.upload_file(local_pkg_path, remote_pkg_path)
                await self._install_file(remote_pkg_path)
                await self._conn.create_process(["rm", "-f", remote_pkg_path]).execute()
            await self._conn.create_process(["nordvpnlite", "--version"]).execute()
        except ProcessExecError as e:
            raise RuntimeError(f"nordvpnlite install failed: {e}") from e

    async def _copy_test_certificate(self) -> None:
        await self._conn.create_process(["mkdir", "-p", OWR_CERT_PATH]).execute()
        await self._conn.upload_file(
            get_root_path(f"{NATLAB_DATA_PATH}core_api/{CERT_FILE_NAME}"),
            f"{OWR_CERT_PATH}{CERT_FILE_NAME}",
        )

    @abstractmethod
    async def _uninstall_existing(self) -> None: ...

    @abstractmethod
    async def _add_signing_key(self) -> None: ...

    @abstractmethod
    async def _disable_default_feeds(self) -> None: ...

    @abstractmethod
    async def _add_custom_feed(self) -> None: ...

    @abstractmethod
    async def _update_and_install(self) -> None: ...

    @abstractmethod
    async def _install_file(self, remote_pkg_path: str) -> None: ...


class _OpkgPackageManager(_OpenwrtPackageManager):
    PUB_KEY_NAME = "nordvpnlite-feed.pub"
    PKG_EXT = "ipk"

    def cdn_files(self) -> list[tuple[str, str]]:
        return [
            (f"{self._cfg.dist_path}{self.pkg_name}", self._cfg.feed_dir),
            (f"{self._cfg.dist_path}Packages", self._cfg.feed_dir),
            (f"{self._cfg.dist_path}Packages.gz", self._cfg.feed_dir),
            (f"{self._cfg.dist_path}Packages.sig", self._cfg.feed_dir),
            (f"{self._cfg.dist_path}{self.PUB_KEY_NAME}", CDN_WEB_ROOT),
        ]

    @property
    def pkg_name(self) -> str:
        return f"nordvpnlite_0.2.0-r1_{self._cfg.cdn_arch}.ipk"

    async def _uninstall_existing(self) -> None:
        try:
            await self._conn.create_process(["opkg", "remove", "nordvpnlite"]).execute()
        except ProcessExecError:
            pass

    async def _add_signing_key(self) -> None:
        pub_key_url = f"{CDN_BASE_URL}/{self.PUB_KEY_NAME}"
        await self._conn.create_process(
            ["wget", "-q", "-O", "/tmp/nordvpn-feed.pub", pub_key_url]
        ).execute()
        await self._conn.create_process(
            ["opkg-key", "add", "/tmp/nordvpn-feed.pub"]
        ).execute()
        await self._conn.create_process(["rm", "/tmp/nordvpn-feed.pub"]).execute()

    async def _disable_default_feeds(self) -> None:
        await self._conn.create_process(
            ["sh", "-c", "> /etc/opkg/distfeeds.conf"]
        ).execute()

    async def _add_custom_feed(self) -> None:
        await self._conn.create_process([
            "sh",
            "-c",
            f'echo "src/gz nordvpn {self._cfg.feed_url}" > {CUSTOM_FEEDS_CONF}',
        ]).execute()

    async def _update_and_install(self) -> None:
        await self._conn.create_process(["opkg", "update"]).execute()
        await self._conn.create_process(["opkg", "install", "nordvpnlite"]).execute()

    async def _install_file(self, remote_pkg_path: str) -> None:
        await self._conn.create_process(["opkg", "install", remote_pkg_path]).execute()


class _ApkPackageManager(_OpenwrtPackageManager):
    PUB_KEY_NAME = "nordvpnlite-apk.rsa.pub"
    PKG_EXT = "apk"

    def cdn_files(self) -> list[tuple[str, str]]:
        return [
            (f"{self._cfg.dist_path}{self.pkg_name}", self._cfg.feed_dir),
            (f"{self._cfg.dist_path}packages.adb", self._cfg.feed_dir),
            (f"{self._cfg.dist_path}{self.PUB_KEY_NAME}", CDN_WEB_ROOT),
        ]

    @property
    def pkg_name(self) -> str:
        return "nordvpnlite-0.2.0-r1.apk"

    async def _uninstall_existing(self) -> None:
        try:
            await self._conn.create_process(["apk", "del", "nordvpnlite"]).execute()
        except ProcessExecError:
            pass

    async def _add_signing_key(self) -> None:
        pub_key_url = f"{CDN_BASE_URL}/{self.PUB_KEY_NAME}"
        await self._conn.create_process(
            ["wget", "-q", "-O", f"/etc/apk/keys/{self.PUB_KEY_NAME}", pub_key_url]
        ).execute()

    async def _disable_default_feeds(self) -> None:
        await self._conn.create_process(
            ["sh", "-c", "> /etc/apk/repositories"]
        ).execute()
        await self._conn.create_process(
            ["sh", "-c", "rm -f /etc/apk/repositories.d/*"]
        ).execute()

    async def _add_custom_feed(self) -> None:
        await self._conn.create_process(
            ["mkdir", "-p", "/etc/apk/repositories.d"]
        ).execute()
        await self._conn.create_process([
            "sh",
            "-c",
            f'echo "{self._cfg.feed_url}/packages.adb" > /etc/apk/repositories.d/nordvpn.list',
        ]).execute()

    async def _update_and_install(self) -> None:
        await self._conn.create_process(["apk", "update"]).execute()
        await self._conn.create_process(["apk", "add", "nordvpnlite"]).execute()

    async def _install_file(self, remote_pkg_path: str) -> None:
        # Unsigned local build, no index to verify it against.
        await self._conn.create_process(
            ["apk", "add", "--allow-untrusted", remote_pkg_path]
        ).execute()


OPENWRT_VM_CONFIG = {
    ConnectionTag.VM_OPENWRT_GW_1: OpenwrtVmConfig(
        "25.12.0", "x86_64", "x86_64", PkgManager.APK, "x86_64"
    ),
    ConnectionTag.VM_OPENWRT_GW_3: OpenwrtVmConfig(
        "24.10.4", "mipsel_24kc", "ramips-mt7621", PkgManager.OPKG, "mipsel"
    ),
}

_PKG_MANAGERS = {
    PkgManager.OPKG: _OpkgPackageManager,
    PkgManager.APK: _ApkPackageManager,
}


async def _copy_artifacts_to_cdn(
    cdn_ssh_connection: asyncssh.SSHClientConnection,
    files: list[tuple[str, str]],
) -> None:
    dirs = set(dst_dir for _, dst_dir in files)
    for d in dirs:
        await cdn_ssh_connection.run(f"mkdir -p {d}", check=True)
    for src, dst_dir in files:
        filename = os.path.basename(src)
        await asyncssh.scp(
            get_root_path(src),
            (cdn_ssh_connection, f"{dst_dir}{filename}"),
        )


async def copy_binaries(
    connection: Connection,
    tag: ConnectionTag,
) -> None:
    cfg = OPENWRT_VM_CONFIG[tag]
    pkg_manager = _PKG_MANAGERS[cfg.pkg_manager](connection, cfg)
    if not _USE_FEED:
        await pkg_manager.install_nordvpnlite(pkg_manager.local_package())
        return
    async with asyncssh.connect(
        CDN_HOST,
        username="root",
        password="",
        known_hosts=None,
        agent_path=None,
    ) as cdn_ssh_connection:
        await _copy_artifacts_to_cdn(cdn_ssh_connection, pkg_manager.cdn_files())
    await pkg_manager.install_nordvpnlite()
